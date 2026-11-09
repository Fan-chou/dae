#!/usr/bin/env python3
"""Controlled real-BPF TCP handoff benchmark. Run as root on an idle Linux host.

Creates a private veth/netns, SOCKS proxy, echo server and iperf server. Refuses
existing dae resources; never replaces an installed binary or configuration.
Compares connect+echo and established echo RTT, throughput, process CPU,
forced-GC heaps and persistent connections across reloads. Results are local
synthetic measurements, not Internet latency estimates.
"""
import argparse
import json
import math
import os
from pathlib import Path
import re
import signal
import shutil
import socket
import subprocess
import sys
import threading
import time
import urllib.request

NS = 'kdae-handoff-test'
LINK = 'kdhandoff0'
IP = '198.21.7.2'


def command(*args, **kw):
    return subprocess.run(args, check=True, **kw)


def exact(s, n):
    b = b''
    while len(b) < n:
        part = s.recv(n-len(b))
        if not part:
            raise EOFError('connection closed')
        b += part
    return b


def server():
    def echo(c):
        with c:
            while data := c.recv(65536):
                c.sendall(data)

    def socks(c):
        upstream = None
        try:
            h = exact(c, 2)
            exact(c, h[1]); c.sendall(b'\x05\x00')
            h = exact(c, 4)
            if h[:3] != b'\x05\x01\x00':
                raise ValueError('CONNECT required')
            if h[3] == 1:
                host = socket.inet_ntoa(exact(c, 4))
            elif h[3] == 3:
                host = exact(c, exact(c, 1)[0]).decode()
            else:
                raise ValueError('IPv4/domain only')
            port = int.from_bytes(exact(c, 2), 'big')
            upstream = socket.create_connection((host, port), timeout=10)
            upstream.settimeout(None)
            upstream.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            c.sendall(b'\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00')
            def copy(a, b):
                try:
                    while data := a.recv(65536):
                        b.sendall(data)
                except OSError:
                    pass
                try:
                    b.shutdown(socket.SHUT_WR)
                except OSError:
                    pass
            worker = threading.Thread(target=copy, args=(c, upstream))
            worker.start(); copy(upstream, c); worker.join()
        except (OSError, EOFError, ValueError):
            pass
        finally:
            c.close()
            if upstream:
                upstream.close()

    def listen(port, handler):
        with socket.socket() as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((IP, port)); s.listen(1024)
            while True:
                c, _ = s.accept()
                c.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                threading.Thread(target=handler, args=(c,), daemon=True).start()
    threading.Thread(target=listen, args=(18080, echo), daemon=True).start()
    listen(1080, socks)


def connect():
    s = socket.create_connection((IP, 18080), timeout=5)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    return s


def exchange(s):
    payload = b'handoff-payload-' + b'x'*49
    s.sendall(payload)
    if exact(s, len(payload)) != payload:
        raise ValueError('payload mismatch')


def distribution(values):
    ordered = sorted(values)
    return {'n': len(values), 'p50_ms': ordered[math.ceil(len(values)*.50)-1],
            'p95_ms': ordered[math.ceil(len(values)*.95)-1],
            'p99_ms': ordered[math.ceil(len(values)*.99)-1], 'max_ms': ordered[-1]}


def cpu(pid):
    stat = Path(f'/proc/{pid}/stat').read_text().split()
    return (int(stat[13])+int(stat[14]))/os.sysconf('SC_CLK_TCK')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary', action='append', required=True, help='LABEL=/absolute/binary')
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--rounds', type=int, default=3)
    p.add_argument('--samples', type=int, default=1000)
    p.add_argument('--reloads', type=int, default=8)
    p.add_argument('--throughput-seconds', type=int, default=10)
    p.add_argument('--offload', action='store_true')
    args = p.parse_args()
    if os.geteuid() != 0:
        p.error('root required')
    if subprocess.run(['pidof','dae'], stdout=subprocess.DEVNULL).returncode == 0:
        p.error('existing dae process')
    for link in (LINK, 'dae0'):
        if subprocess.run(['ip','link','show',link], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0:
            p.error('existing interface '+link)
    namespaces = command('ip','netns','list', capture_output=True, text=True).stdout
    if any(n in namespaces.split() for n in (NS, 'daens')) or Path('/sys/fs/bpf/dae').exists():
        p.error('existing dae/test namespace or BPF pins')
    args.output.mkdir(parents=True, exist_ok=False)
    binaries = [(label, str(Path(binary).resolve())) for label,binary in (v.split('=',1) for v in args.binary)]
    processes = []
    created_ns = created_link = False
    results = []
    try:
        command('ip','netns','add',NS); created_ns = True
        command('ip','link','add',LINK,'type','veth','peer','name','kdhandoffp'); created_link = True
        command('ip','link','set','kdhandoffp','netns',NS)
        command('ip','addr','add','198.21.7.1/24','dev',LINK)
        command('ip','link','set',LINK,'up')
        command('ip','netns','exec',NS,'ip','link','set','lo','up')
        command('ip','netns','exec',NS,'ip','addr','add',IP+'/24','dev','kdhandoffp')
        command('ip','netns','exec',NS,'ip','link','set','kdhandoffp','up')
        processes.append(subprocess.Popen(['ip','netns','exec',NS,sys.executable,__file__,'--server']))
        processes.append(subprocess.Popen(['ip','netns','exec',NS,'iperf3','-s','-p','18081'], stdout=subprocess.DEVNULL))
        time.sleep(.3)
        config = args.output/'config.dae'
        # A deterministic, nonmatching userspace rule set makes retained policy
        # memory visible; all measured traffic uses the SOCKS proxy fallback.
        domains = ', '.join('suffix:rule%d.handoff.invalid'%i for i in range(12000))
        config.write_text('''global {
 wan_interface: %s
 disable_waiting_network: true
 dial_mode: ip
 pprof_port: 16060
 log_level: info
}
node { 'socks5://%s:1080#fixture' }
group { proxy { policy: fixed(0) } }
routing {
 domain(%s) -> block
 fallback: proxy
}
''' % (LINK,IP,domains))
        config.chmod(0o600)
        for round_no in range(args.rounds):
            order = binaries if round_no%2 == 0 else list(reversed(binaries))
            for label,binary in order:
                dest = args.output/f'{round_no+1}-{label}'; dest.mkdir()
                env = dict(os.environ, GOMAXPROCS='2', GOMEMLIMIT='512MiB',
                           DAE_ALLOW_TCP_SOCKMAP='1' if args.offload else '0')
                log_file = (dest/'daemon.log').open('w')
                proc = subprocess.Popen([binary,'run','-c',str(config),'--disable-sudo','--disable-pidfile','--disable-timestamp'], env=env, stdout=log_file, stderr=subprocess.STDOUT)
                held=[]
                try:
                    def wait_for(text, count=1):
                        deadline=time.monotonic()+45
                        while time.monotonic()<deadline:
                            log=(dest/'daemon.log').read_text()
                            if proc.poll() is not None:
                                raise RuntimeError('daemon exited: '+log[-3000:])
                            if log.count(text)>=count:
                                return
                            time.sleep(.1)
                        raise TimeoutError('waiting for '+text)
                    wait_for('Control plane built')
                    time.sleep(.5)
                    for _ in range(30):
                        with connect() as s: exchange(s)
                    begin_cpu=cpu(proc.pid); begin=time.monotonic()
                    timings=[]
                    for _ in range(args.samples):
                        start=time.perf_counter_ns()
                        with connect() as s: exchange(s)
                        timings.append((time.perf_counter_ns()-start)/1e6)
                    persistent=[]
                    with connect() as s:
                        for _ in range(args.samples):
                            start=time.perf_counter_ns(); exchange(s)
                            persistent.append((time.perf_counter_ns()-start)/1e6)
                    result={'round':round_no+1,'label':label,'offload':args.offload,
                            'connect_echo':distribution(timings),'established_echo':distribution(persistent),
                            'latency_wall_s':time.monotonic()-begin,'latency_dae_cpu_s':cpu(proc.pid)-begin_cpu}
                    throughput_cpu=cpu(proc.pid)
                    iperf=command('iperf3','-c',IP,'-p','18081','-t',str(args.throughput_seconds),'-J',capture_output=True,text=True)
                    result['throughput_dae_cpu_s']=cpu(proc.pid)-throughput_cpu
                    (dest/'iperf.json').write_text(iperf.stdout)
                    result['throughput_bps']=json.loads(iperf.stdout)['end']['sum_received']['bits_per_second']
                    def profile(index):
                        base='http://127.0.0.1:16060/debug/pprof/'
                        data=urllib.request.urlopen(base+'heap?gc=1',timeout=30).read()
                        (dest/f'heap-{index}.prof').write_bytes(data)
                        gor=urllib.request.urlopen(base+'goroutine?debug=2',timeout=10).read()
                        (dest/f'goroutine-{index}.txt').write_bytes(gor)
                        mem=urllib.request.urlopen(base+'heap?gc=1&debug=1',timeout=30).read().decode()
                        (dest/f'heap-{index}.txt').write_text(mem)
                        return {'heap_alloc':int(re.search(r'# HeapAlloc = (\d+)',mem)[1]),
                                'fds':len(list(Path(f'/proc/{proc.pid}/fd').iterdir()))}
                    result['memory']=[profile(0)]
                    reload_latencies=[]
                    reload_errors=[]
                    for reload_no in range(1,args.reloads+1):
                        for _ in range(8):
                            s=connect(); exchange(s); held.append(s)
                        stop=threading.Event()
                        def monitor():
                            try:
                                with connect() as probe:
                                    while not stop.is_set():
                                        started=time.perf_counter_ns();exchange(probe)
                                        reload_latencies.append((time.perf_counter_ns()-started)/1e6)
                                        stop.wait(.002)
                            except Exception as exc:
                                reload_errors.append(str(exc))
                        thread=threading.Thread(target=monitor);thread.start()
                        try:
                            os.kill(proc.pid,signal.SIGUSR1)
                            wait_for('[Reload] Finished',reload_no)
                            wait_for('[Reload] Retired old control plane',reload_no)
                        finally:
                            stop.set();thread.join(timeout=6)
                            if thread.is_alive(): raise RuntimeError('reload latency monitor stuck')
                        for s in held: exchange(s)
                        result['memory'].append(profile(reload_no))
                    result['reload_echo']=distribution(reload_latencies) if reload_latencies else None
                    result['reload_errors']=reload_errors
                    if reload_errors: raise RuntimeError('connection failed during reload: '+repr(reload_errors))
                    result['surviving_connections']=len(held)
                    stacks=(dest/f'goroutine-{args.reloads}.txt').read_text()
                    result['active_offload_stacks']=stacks.count('(*tcpRelayOffloadSession).Run(')
                    if args.offload and held and not result['active_offload_stacks']:
                        raise RuntimeError('offload requested but no active offload sessions observed')
                    for s in held: s.close()
                    held.clear()
                    time.sleep(.5)
                    result['after_close']=profile('closed')
                    results.append(result)
                    (args.output/'results.json').write_text(json.dumps(results,indent=2)+'\n')
                    print(json.dumps(result),flush=True)
                finally:
                    for s in held: s.close()
                    proc.terminate()
                    try: proc.wait(timeout=15)
                    except subprocess.TimeoutExpired: proc.kill(); proc.wait()
                    log_file.close()
                time.sleep(.3)
    finally:
        for proc in processes:
            proc.terminate()
        for proc in processes:
            try: proc.wait(timeout=5)
            except subprocess.TimeoutExpired: proc.kill(); proc.wait()
        # These resources were absent at entry and belong to this fixture.
        for ns in ('daens', NS if created_ns else ''):
            if ns: subprocess.run(['ip','netns','del',ns],stderr=subprocess.DEVNULL)
        if created_ns and Path('/sys/fs/bpf/dae').exists():
            shutil.rmtree('/sys/fs/bpf/dae')
        for link in ('dae0', LINK if created_link else ''):
            if link: subprocess.run(['ip','link','del',link],stderr=subprocess.DEVNULL)


if __name__ == '__main__':
    if sys.argv[1:] == ['--server']:
        server()
    else:
        main()
