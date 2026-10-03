#!/usr/bin/env python3
"""Run the opt-in gateway fixture with an independently verified HTTPS client.

Compile control.test with CGO_ENABLED=0, copy it to the gateway, and explicitly
supply both private hosts and node labels. This tool changes no daemon config.
Only a complete, TLS-verified 1 MiB response matching the twice-checked baseline
is accepted. Artifacts stay in --output; node credentials stay on the gateway.
"""

import argparse
import hashlib
import itertools
import json
from pathlib import Path
import shlex
import subprocess
import time


CLIENT = r'''
import hashlib, json, subprocess, sys, tempfile
from pathlib import Path
with tempfile.TemporaryDirectory(prefix='kdae-wan-client-') as directory:
    body = Path(directory) / 'body'
    command = ['curl', '--disable', '--no-insecure', '-4', '--http1.1', '--max-time', '30',
               '--connect-timeout', '8', '-sS', '-o', str(body), '-w', '%{json}',
               '-H', 'Connection: close']
    if sys.argv[1] != 'baseline':
        command += ['--proxy', 'http://' + sys.argv[1], '--noproxy', '']
    else:
        command += ['--proxy', '', '--noproxy', '*']
    command += ['https://speed.cloudflare.com/__down?bytes=1048576']
    result = subprocess.run(command, capture_output=True, text=True, timeout=35)
    data = body.read_bytes() if body.exists() else b''
    metadata = json.loads(result.stdout) if result.stdout else {}
    print(json.dumps({'exit': result.returncode, 'http': metadata.get('http_code'),
        'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest(),
        'seconds': metadata.get('time_total'),
        'tls_seconds': metadata.get('time_appconnect'),
        'first_byte_seconds': metadata.get('time_starttransfer'),
        'speed_bytes_per_second': metadata.get('speed_download'),
        'ssl_verify_result': metadata.get('ssl_verify_result'),
        'error': result.stderr}))
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--gateway', required=True, help='SSH destination')
    parser.add_argument('--bind', required=True, help='gateway private IPv4')
    parser.add_argument('--client', required=True, help='client SSH destination')
    parser.add_argument('--client-ip', required=True, help='allowed private IPv4')
    parser.add_argument('--remote-binary', required=True)
    parser.add_argument('--node', action='append', required=True)
    parser.add_argument('--rounds', type=int, choices=range(1, 4), default=3)
    parser.add_argument('--mss', type=int, choices=[0, 1380], action='append',
                        help='restrict MSS matrix; default tests both values')
    parser.add_argument('--split-prefix', action='store_true',
                        help='controlled two-segment TLS prefix; not natural traffic')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    ssh_options = ['ssh', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=8']

    def gateway(command, **kwargs):
        return subprocess.run(ssh_options + [args.gateway, command],
                              capture_output=True, text=True, timeout=15, **kwargs)

    def client(address):
        result = subprocess.run(ssh_options + [args.client,
            shlex.join(['python3', '-', address])], input=CLIENT,
            capture_output=True, text=True, timeout=45)
        if result.returncode:
            raise RuntimeError('client SSH failed: ' + result.stderr)
        return json.loads(result.stdout)

    expected_hash = hashlib.sha256(b'0' * 1048576).hexdigest()

    def valid_client(result):
        return (result['exit'] == 0 and result['http'] == 200
                and result['bytes'] == 1048576
                and result['sha256'] == expected_hash
                and result['ssl_verify_result'] == 0)

    baseline = [client('baseline') for _ in range(2)]
    (args.output / 'baseline.json').write_text(json.dumps(baseline, indent=2) + '\n')
    if not all(map(valid_client, baseline)):
        raise RuntimeError('baseline response changed or HTTPS validation failed')

    directory_result = gateway('mktemp -d /tmp/kdae-wan.XXXXXX')
    remote_directory = directory_result.stdout.strip()
    if directory_result.returncode or not remote_directory.startswith('/tmp/kdae-wan.') or '\n' in remote_directory:
        raise RuntimeError('could not create private fixture workspace')
    mss_values = args.mss if args.mss is not None else [0, 1380]
    conditions = list(itertools.product(args.node, mss_values, mss_values, [False, True]))
    results = []
    try:
        for round_number in range(1, args.rounds + 1):
            ordered = conditions if round_number % 2 else conditions[::-1]
            for node, dial_mss, listen_mss, coalesce in ordered:
                index = len(results) + 1
                ready = remote_directory + '/ready.json'
                environment = {
                    'DAE_TEST_TCP_PROXY_WAN': '1', 'DAE_TEST_TCP_WAN_NODE': node,
                    'DAE_TEST_TCP_WAN_BIND': args.bind,
                    'DAE_TEST_TCP_WAN_CLIENT': args.client_ip,
                    'DAE_TEST_TCP_WAN_READY': ready,
                    'DAE_TEST_TCP_WAN_DIAL_MSS': str(dial_mss),
                    'DAE_TEST_TCP_WAN_LISTEN_MSS': str(listen_mss),
                    'DAE_TCP_WRAPPED_GATHER': str(coalesce).lower(),
                    'DAE_TEST_TCP_WAN_PREFIX_PARTS': '2' if args.split_prefix else '1',
                    'GOMAXPROCS': '2',
                }
                command = shlex.join(['env'] + [k + '=' + v for k, v in environment.items()]
                    + [args.remote_binary, '-test.run', '^TestTCPProxyWANLive$',
                       '-test.timeout', '65s', '-test.v'])
                process = subprocess.Popen(ssh_options + [args.gateway, command],
                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
                metadata = None
                delivery = None
                log = ''
                error = None
                try:
                    deadline = time.monotonic() + 12
                    while time.monotonic() < deadline and process.poll() is None:
                        read = gateway(shlex.join(['cat', ready]))
                        if read.returncode == 0:
                            metadata = json.loads(read.stdout)
                            break
                        time.sleep(0.2)
                    if metadata and not metadata['address'].startswith(args.bind + ':'):
                        raise RuntimeError('unexpected fixture bind address')
                    delivery = client(metadata['address']) if metadata else None
                    log, _ = process.communicate(timeout=70)
                except Exception as exc:
                    error = str(exc)
                finally:
                    if process.poll() is None:
                        # The remote test also has its own timeout and socket
                        # deadlines, so a lost SSH transport cannot park it.
                        process.terminate()
                        try:
                            log, _ = process.communicate(timeout=5)
                        except subprocess.TimeoutExpired:
                            process.kill()
                            log, _ = process.communicate()
                    elif not log:
                        log, _ = process.communicate()
                (args.output / ('fixture-%03d.log' % index)).write_text(log)
                lines = [line[len('WAN_RESULT '):] for line in log.splitlines()
                         if line.startswith('WAN_RESULT ')]
                try:
                    fixture = json.loads(lines[0]) if len(lines) == 1 else None
                except ValueError as exc:
                    fixture = None
                    error = str(exc)
                expected = {'node': node, 'dial_mss': dial_mss,
                            'listen_mss': listen_mss, 'coalesce': coalesce,
                            'prefix_parts': 2 if args.split_prefix else 1}
                matched = fixture and metadata and all(
                    fixture.get(k) == v and metadata.get(k) == v
                    for k, v in expected.items())
                if args.split_prefix and fixture:
                    # Confirm the controlled workload actually reached the
                    # two-segment candidate and observed the expected first
                    # Write size, rather than treating its switch as evidence.
                    matched = matched and fixture['prefix_segments'] == 2
                    matched = matched and fixture['gather_body_bytes'] == 0
                    first = fixture['prefix_bytes'] if coalesce else fixture['prefix_bytes'] // 2
                    matched = matched and fixture['first_write_bytes'] == first
                result = {'index': index, 'round': round_number, **expected,
                    'client': delivery, 'fixture': fixture,
                    'fixture_exit': process.returncode, 'error': error,
                    'valid': bool(not error and process.returncode == 0 and matched
                                  and delivery and valid_client(delivery))}
                results.append(result)
                with (args.output / 'results.jsonl').open('a') as output:
                    output.write(json.dumps(result, sort_keys=True) + '\n')
                print(json.dumps({'index': index, 'round': round_number, **expected,
                    'valid': result['valid'],
                    'seconds': delivery.get('seconds') if delivery else None}), flush=True)
                if not result['valid']:
                    raise RuntimeError('WAN sample failed; preserved client and fixture evidence')
    finally:
        try:
            remove = gateway(shlex.join(['rm', '-f', remote_directory + '/ready.json',
                                         remote_directory + '/ready.json.next']))
            cleanup = gateway(shlex.join(['rmdir', remote_directory]))
            if remove.returncode or cleanup.returncode:
                print('fixture workspace cleanup failed: ' + remote_directory, flush=True)
        except Exception as exc:
            print('fixture workspace cleanup failed: ' + str(exc), flush=True)
    print(json.dumps({'completed': len(results), 'valid': sum(r['valid'] for r in results)}), flush=True)


if __name__ == '__main__':
    main()
