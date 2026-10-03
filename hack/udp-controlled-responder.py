#!/usr/bin/env python3
"""Return bounded synthetic DNS replies on a proxy server's loopback only.

Run with ``python3 -u`` on the server, then use test-udp-proxy-wan.py with
--target 127.0.0.1:46663 and an explicit proxy node. It accepts at most 48
requests over 12 minutes and preserves each request's size in its reply.
"""

import json
import os
import signal
import socket
import struct
import time

stop = False


def finish(signum, frame):
    global stop
    stop = True


def allowed(data):
    if not 64 <= len(data) <= 1800:
        return False
    _, flags, qd, an, ns, ar = struct.unpack('!HHHHHH', data[:12])
    if flags & 0xf800 or (qd, an, ns, ar) != (1, 0, 0, 1):
        return False
    at, labels = 12, []
    while at < len(data):
        size = data[at]
        at += 1
        if size == 0:
            break
        if size > 63 or at + size > len(data):
            return False
        labels.append(data[at:at + size])
        at += size
    if at + 19 > len(data):
        return False
    qtype, qclass = struct.unpack('!HH', data[at:at + 4])
    name = b'.'.join(labels)
    if qclass != 1 or (name, qtype) not in ((b'one.one.one.one', 1), (b'cloudflare.com', 16)):
        return False
    at += 4
    if data[at] != 0:
        return False
    kind, size, ttl, length = struct.unpack('!HHIH', data[at + 1:at + 11])
    if kind != 41 or size not in (1232, 4096) or ttl != 0 or at + 11 + length != len(data):
        return False
    code, count = struct.unpack('!HH', data[at + 11:at + 15])
    return code == 65001 and count == length - 4 and not any(data[at + 15:])


def main():
    signal.signal(signal.SIGTERM, finish)
    signal.signal(signal.SIGINT, finish)
    summary = {'received': 0, 'accepted': 0, 'replied': 0, 'invalid': 0, 'sizes': {}}
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('127.0.0.1', 46663))
    sock.settimeout(.5)
    print(json.dumps({'ready': True, 'pid': os.getpid(), 'bind': '127.0.0.1:46663',
                      'ttl_seconds': 720, 'max_requests': 48}), flush=True)
    deadline = time.monotonic() + 720
    try:
        while not stop and time.monotonic() < deadline and summary['received'] < 48:
            try:
                data, peer = sock.recvfrom(1801)
            except socket.timeout:
                continue
            summary['received'] += 1
            if not allowed(data):
                summary['invalid'] += 1
                continue
            summary['accepted'] += 1
            reply = data[:2] + bytes([data[2] | 0x80]) + data[3:]
            sock.sendto(reply, peer)
            summary['replied'] += 1
            key = str(len(reply))
            summary['sizes'][key] = summary['sizes'].get(key, 0) + 1
    finally:
        sock.close()
        print(json.dumps({'complete': True, 'stats': summary}), flush=True)


if __name__ == '__main__':
    main()
