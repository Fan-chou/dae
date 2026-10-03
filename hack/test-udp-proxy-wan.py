#!/usr/bin/env python3
"""Compare bounded synthetic DNS sizes over direct and configured UDP nodes.

The gateway fixture reads node credentials in place. The client generates its
own payload and verifies DNS transaction/question independently; no game data,
node URI, interface MTU or production daemon configuration is changed.
Query sizes use a zero-filled private-use EDNS option (65001). Public resolver
policy can affect delivery; these probes cannot establish a game path MTU.
For deterministic reply sizes, run udp-controlled-responder.py on the proxy
server and select --target 127.0.0.1:46663 with an explicit proxy node.
"""

import argparse
import itertools
import json
from pathlib import Path
import shlex
import subprocess
import time


CLIENT = r'''
import json, socket, struct, sys, time
host, port = sys.argv[1].rsplit(':', 1)
cases = json.loads(sys.argv[2])
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.settimeout(7)
sock.connect((host, int(port)))
results = []
def read_name(data, offset):
    labels, visited, end = [], set(), None
    while True:
        if offset in visited or offset >= len(data):
            raise ValueError('invalid DNS name')
        visited.add(offset)
        size = data[offset]
        if size & 0xc0 == 0xc0:
            if offset + 1 >= len(data):
                raise ValueError('truncated DNS pointer')
            if end is None:
                end = offset + 2
            offset = ((size & 0x3f) << 8) | data[offset + 1]
        elif size & 0xc0:
            raise ValueError('invalid DNS label')
        elif size == 0:
            return '.'.join(labels).lower(), end if end is not None else offset + 1
        else:
            offset += 1
            if offset + size > len(data):
                raise ValueError('truncated DNS label')
            labels.append(data[offset:offset + size].decode('ascii'))
            offset += size
for index, case in enumerate(cases):
    txid = 1000 + index
    name = 'one.one.one.one' if case['qtype'] == 1 else 'cloudflare.com'
    qname = b''.join(bytes([len(x)]) + x.encode() for x in name.split('.')) + b'\0'
    question = qname + struct.pack('!HH', case['qtype'], 1)
    header = struct.pack('!HHHHHH', txid, 0x0100, 1, 0, 0, 1)
    pad = case['bytes'] - len(header) - len(question) - 15
    assert 0 <= pad <= 1800
    opt = b'\0' + struct.pack('!HHIH', 41, case['edns'], 0, 4 + pad)
    request = header + question + opt + struct.pack('!HH', 65001, pad) + bytes(pad)
    assert len(request) == case['bytes']
    started = time.monotonic()
    sock.send(request)
    result = dict(case, index=index, id=txid, reply_valid=False)
    try:
        reply = sock.recv(8192)
        result['reply_bytes'] = len(reply)
        if reply == b'UDP_WAN_ERROR':
            result['fixture_error'] = True
        else:
            rid, flags, qd, an, ns, ar = struct.unpack('!HHHHHH', reply[:12])
            response_name, offset = read_name(reply, 12)
            response_type, response_class = struct.unpack('!HH', reply[offset:offset+4])
            result.update(rcode=flags & 15, truncated=bool(flags & 0x200), answers=an)
            result['reply_valid'] = (rid == txid and bool(flags & 0x8000)
                and qd == 1 and response_name == name
                and response_type == case['qtype'] and response_class == 1)
    except (OSError, ValueError, struct.error) as error:
        result['error_type'] = type(error).__name__
    result['milliseconds'] = round((time.monotonic() - started) * 1000)
    results.append(result)
sock.close()
print(json.dumps(results))
'''


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--gateway', required=True)
    p.add_argument('--bind', required=True)
    p.add_argument('--client', required=True)
    p.add_argument('--client-ip', required=True)
    p.add_argument('--remote-binary', required=True)
    p.add_argument('--node', action='append', required=True)
    p.add_argument('--receiver-node', action='append', default=[])
    p.add_argument('--target', choices=['1.1.1.1:53', '8.8.8.8:53', '127.0.0.1:46663'], action='append',
                   help='loopback target requires a bounded responder on the selected proxy server')
    p.add_argument('--rounds', type=int, choices=[1, 2], default=2)
    p.add_argument('--size', type=int, metavar='BYTES', action='append',
                   help='override A-query sizes for a smaller follow-up batch')
    p.add_argument('--output', type=Path, required=True)
    args = p.parse_args()
    if '127.0.0.1:46663' in (args.target or []) and 'direct' in args.node + args.receiver_node:
        p.error('the controlled loopback responder requires explicit proxy nodes')
    args.output.mkdir(parents=True, exist_ok=False)
    ssh = ['ssh', '-oBatchMode=yes', '-oConnectTimeout=8']

    def gateway(command):
        return subprocess.run(ssh + [args.gateway, shlex.join(['sh', '-c', command])],
                              capture_output=True, text=True, timeout=15)

    made = gateway('umask 077; mktemp -d /tmp/kdae-udp-wan.XXXXXX')
    directory = made.stdout.strip()
    if made.returncode or not directory.startswith('/tmp/kdae-udp-wan.') or '\n' in directory:
        raise RuntimeError('private gateway workspace failed')
    sizes = args.size or [64, 512, 1000, 1200, 1232, 1240, 1250, 1260, 1300, 1350, 1400, 1700]
    if any(size < 64 or size > 1800 for size in sizes):
        p.error('query sizes must be between 64 and 1800 bytes')
    if len(sizes) > 22:
        p.error('at most 22 query sizes (48 total probes)')
    prototypes = [dict(bytes=size, qtype=1, edns=4096) for size in sizes]
    prototypes += [dict(bytes=64, qtype=16, edns=size) for size in [1232, 4096]]
    cases = []
    for round_number in range(args.rounds):
        ordered = prototypes if round_number % 2 == 0 else prototypes[::-1]
        cases.extend(dict(case, round=round_number + 1) for case in ordered)
    conditions = [(n, 'read_from') for n in args.node]
    conditions += [(n, 'packet_receiver') for n in args.receiver_node]
    results = []
    try:
        for index, ((node, mode), target) in enumerate(itertools.product(conditions, args.target or ['1.1.1.1:53'])):
            ready = directory + '/ready.json'
            environment = {'DAE_TEST_UDP_PROXY_WAN': '1', 'DAE_TEST_UDP_WAN_BIND': args.bind,
                'DAE_TEST_UDP_WAN_CLIENT': args.client_ip, 'DAE_TEST_UDP_WAN_NODE': node,
                'DAE_TEST_UDP_WAN_TARGET': target, 'DAE_TEST_UDP_WAN_READ_MODE': mode,
                'DAE_TEST_UDP_WAN_READY': ready, 'DAE_TEST_UDP_WAN_REQUESTS': str(len(cases)),
                'GOMAXPROCS': '2', 'GOMEMLIMIT': '64MiB'}
            command = shlex.join(['env'] + [k + '=' + v for k, v in environment.items()]
                + [args.remote_binary, '-test.run', '^TestUDPProxyWANLive$', '-test.timeout', '250s', '-test.v'])
            log_path = args.output / f'fixture-{index:02d}.log'
            log_file = log_path.open('w')
            process = subprocess.Popen(ssh + [args.gateway, command], stdout=log_file,
                stderr=subprocess.STDOUT, text=True)
            log, client, error = '', None, None
            try:
                deadline = time.monotonic() + 12
                metadata = None
                while time.monotonic() < deadline and process.poll() is None:
                    read = gateway(shlex.join(['cat', ready]))
                    if read.returncode == 0:
                        metadata = json.loads(read.stdout)
                        break
                    time.sleep(.2)
                if not metadata or not metadata['address'].startswith(args.bind + ':') or metadata['node'] != node or metadata['target'] != target:
                    raise RuntimeError('fixture readiness mismatch')
                execution = subprocess.run(ssh + [args.client,
                    shlex.join(['python3', '-', metadata['address'], json.dumps(cases)])], input=CLIENT,
                    capture_output=True, text=True, timeout=230)
                if execution.returncode:
                    raise RuntimeError('client SSH or probe process failed')
                client = json.loads(execution.stdout)
                process.wait(timeout=25)
            except Exception as exc:
                error = str(exc)
            finally:
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait()
                log_file.close()
            log = log_path.read_text()
            probes = [json.loads(line[len('UDP_WAN_PROBE '):]) for line in log.splitlines() if line.startswith('UDP_WAN_PROBE ')]
            complete = not error and process.returncode == 0 and len(probes) == len(cases) and client and len(client) == len(cases)
            if complete:
                for i, (a, b) in enumerate(zip(probes, client)):
                    if (a['index'] != i or a['id'] != b['id'] or a['request_bytes'] != b['bytes']
                            or a['response_valid'] != b['reply_valid']
                            or (a['response_valid'] and a['reply_bytes'] != b['reply_bytes'])):
                        complete = False
                        error = 'gateway/client validation mismatch'
                        break
            result = {'node': node, 'target': target, 'read_mode': mode, 'fixture_complete': bool(complete),
                'fixture_exit': process.returncode, 'error': error, 'probes': probes, 'client': client}
            results.append(result)
            (args.output / 'results.json').write_text(json.dumps(results, indent=2) + '\n')
            print(json.dumps({'node': node, 'target': target, 'read_mode': mode,
                'fixture_complete': bool(complete), 'valid_replies': sum(x['response_valid'] for x in probes),
                'attempts': len(probes), 'message_too_long': sum(x.get('message_too_long', False) for x in probes),
                'timeouts': sum(x.get('timeout', False) for x in probes),
                'capability_failures': sum(x.get('error_stage') == 'capability' for x in probes),
                'validation_failures': sum(x.get('error_stage') == 'validation' for x in probes)}), flush=True)
            if not complete:
                raise RuntimeError('fixture failed; artifacts retained')
    finally:
        gateway(shlex.join(['rm', '-rf', directory]))


if __name__ == '__main__':
    main()
