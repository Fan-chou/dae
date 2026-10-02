#!/usr/bin/env python3
"""Convert bounded SmartDNS audit text in memory; never persist raw domains/IPs.
Audit lines expose results, not upstream, RCODE, cache hits or filtering causes.
"""
import argparse
import datetime
import hashlib
import hmac
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import sys
from evidence import validate, SCHEMA

LINE=re.compile(r"^\[([^]]+)\]\s+(\S+) query ([^,]+), type (\d+), time (\d+)ms,.*?group ([^,]+), result\s*(.*)$")
def read_key(path):
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_mode & 0o077:
        raise ValueError("identity key must be a private regular file (0600)")
    descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (info.st_dev, info.st_ino) != (before.st_dev, before.st_ino) or not stat.S_ISREG(info.st_mode) or info.st_size > 66 or info.st_mode & 0o077:
            raise ValueError("identity key must be a private regular file (0600)")
        key = stream.read(67)
    if len(key) != 32:
        try:
            key = bytes.fromhex(key.decode().strip())
        except (ValueError, UnicodeError):
            raise ValueError("identity key must be 32 raw bytes or 64 hex digits") from None
    if len(key) != 32:
        raise ValueError("identity key must be 32 raw bytes or 64 hex digits")
    return key


def identity(key,kind,value):
    if not value:return ""
    return hmac.new(key,(kind+"\0"+value).encode(),hashlib.sha256).hexdigest()[:32]

def parse(line,key):
    if len(key)!=32:raise ValueError("identity key must be 32 bytes")
    match=LINE.match(line.strip())
    if not match:return None
    ts,client,site,qtype,elapsed,group,result=match.groups()
    at=datetime.datetime.strptime(ts,"%Y-%m-%d %H:%M:%S,%f").replace(tzinfo=datetime.timezone(datetime.timedelta(hours=8)))
    elapsed=int(elapsed);ips=[]
    for token in result.split(","):
        try:ips.append(str(ipaddress.ip_address(token.strip())))
        except ValueError:pass
    digest=hmac.new(key,line.strip().encode(),hashlib.sha256).hexdigest()
    generation="smartdns222-"+at.strftime("%Y%m%d")
    e={"schema":SCHEMA,"generation":generation,"sequence":int(digest[:12],16)+1,"id":"audit-"+digest[:32],"flow_id":"audit-"+digest[:32],
       "capture_episode_id":"","kind":"smartdns_audit","scope":{"site_id":identity(key,"site",site.lower().rstrip(".")),"node_id":"","group_id":identity(key,"group",group),"network":"dns","path":"unknown","policy_epoch":0},
       "target_id":"","target_kind":"","client_id":identity(key,"client",client),"start_ms":int(at.timestamp()*1000)-elapsed,"duration_ms":elapsed,
       "outcome":"recorded" if ips else "empty_result","dns":{"qtype":int(qtype),"rcode":None,"answer_ips":len(ips),"fake_ips":sum(ipaddress.ip_address(ip) in ipaddress.ip_network("28.0.0.0/8") for ip in ips if ":" not in ip),"truncated":None,"cache_status":"unknown","filter_reason":"unobserved","upstream_id":"","answer_ids":[identity(key,"address",ip) for ip in ips[:32]]},
       "load":None,"inclusion_probability":None,"source":"smartdns-222","sampling_frame":"audit_tail"}
    validate(e);return e

if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__);p.add_argument("--key-file",type=Path,required=True);a=p.parse_args();key=read_key(a.key_file)
    for line in sys.stdin:
        e=parse(line,key)
        if e:print(json.dumps(e,separators=(",",":")))
