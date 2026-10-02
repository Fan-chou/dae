#!/usr/bin/env python3
"""Bounded SSH collector. Commit cursor only after immutable validated archive.
No labels or model calls; missing pages, generation changes and budgets are explicit.
"""
import argparse
import datetime
import collections
import time
import hashlib
import json
import os
from pathlib import Path
import subprocess
from evidence import validate
from validate import validate as validate_capture
from smartdns_evidence import parse, read_key
from archive_io import atomic_write


def ssh(host, command):
    return subprocess.run(["ssh","-oBatchMode=yes","-oConnectTimeout=5",host,command],check=True,capture_output=True,text=True,timeout=25).stdout

def archive(records, output, provenance, budget):
    data=b"".join((json.dumps(r,sort_keys=True,separators=(",",":"))+"\n").encode() for r in records)
    digest=hashlib.sha256(data).hexdigest()
    day=datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d")
    path=output/(day+"-"+digest+".jsonl")
    if path.exists():
        if path.read_bytes()!=data:raise ValueError("archive corruption")
        # A previous interruption may have left data without its manifest.
    meta=path.with_suffix(".manifest.json")
    if path.exists() and meta.exists():return path
    meta_data=json.dumps(dict(provenance,sha256=digest,records=len(records),review="pending",gold=None),indent=2).encode()+b"\n"
    used=sum(p.stat().st_size for p in output.glob(day+"-*"))
    if used+(0 if path.exists() else len(data))+len(meta_data)>budget:raise ValueError("daily budget exhausted; cursor retained")
    if not path.exists():
        atomic_write(path,data)
    if not meta.exists():
        atomic_write(meta,meta_data)
    return path

def run(args):
    import fcntl
    args.output.mkdir(parents=True,exist_ok=True,mode=0o700)
    with (args.output/"collector.lock").open("a") as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        return run_locked(args)

def run_locked(args):
    statepath=args.output/"cursor.json"
    state=json.loads(statepath.read_text()) if statepath.exists() else {}
    binary=ssh(args.router,"sha256sum /proc/$(pidof dae)/exe").split()[0]
    summary={"binary_sha256":binary,"pages":0,"records":0,"gaps":[]}
    anchors=[a for a in state.get("audit_anchors",[]) if int(time.time()*1000)-a[1]<300000]
    # Preserve recent anchors written by older collectors during migration.
    legacy_anchors = state.get("audit_legacy_anchors", anchors if "audit_flow_anchors" not in state else [])
    legacy_anchors = [a for a in legacy_anchors if int(time.time()*1000)-a[1]<300000]
    flow_anchors = {tuple(a[:2]): a for a in state.get("audit_flow_anchors", []) if int(time.time()*1000)-a[3]<300000}
    for endpoint,validator in (("capture",validate_capture),("evidence",validate)):
        saved=state.get(endpoint,{"after":0,"generation":None})
        for _ in range(args.max_pages):
            snap=json.loads(ssh(args.router,f"sh /usr/libexec/dae/read-observation.sh {endpoint} {int(saved['after'])}"))
            if not snap.get("enabled"):raise ValueError(endpoint+" disabled")
            gen=snap["generation"]
            gap=None
            if saved["generation"] and gen!=saved["generation"]:
                gap={"endpoint":endpoint,"reason":"generation_changed","previous":saved,"current":gen}
                saved={"after":0,"generation":gen}
                summary["gaps"].append(gap)
                # Re-fetch from zero; never use old-generation cursor.
                snap=json.loads(ssh(args.router,f"sh /usr/libexec/dae/read-observation.sh {endpoint} 0"))
                if snap["generation"]!=gen:raise ValueError("generation changed while fetching")
            if snap["oldest_sequence"]>saved["after"]+1:
                gap={"endpoint":endpoint,"reason":"ring_gap","after":saved["after"],"oldest":snap["oldest_sequence"]}
                summary["gaps"].append(gap)
            records=snap["records"]
            if not records:
                state[endpoint] = {"after": saved["after"], "generation": gen}
                atomic_write(statepath,json.dumps(state).encode())
                break
            if ssh(args.router,"sha256sum /proc/$(pidof dae)/exe").split()[0]!=binary:
                raise ValueError("running binary changed during fetch; cursor retained")
            previous=saved["after"]
            for r in records:
                validator(r)
                if endpoint=="evidence" and r["kind"] in {"selection_resolution", "dial"} and r["scope"]["site_id"]:
                    key = (r["generation"], r["flow_id"])
                    old = flow_anchors.get(key)
                    at = min(r["start_ms"], old[3]) if old else r["start_ms"]
                    flow_anchors[key] = [*key, r["scope"]["site_id"], at]
                if r["generation"]!=gen or r["sequence"]<=previous:raise ValueError("invalid page generation/order")
                previous=r["sequence"]
            if previous!=snap["next_sequence"]:raise ValueError("cursor does not match last record")
            archive(records,args.output,{"endpoint":endpoint,"generation":gen,"after":saved["after"],"next":previous,"gap":gap,"binary_sha256":binary,"collector_stats":snap.get("stats",{k:snap[k] for k in ("queue_dropped","ring_evicted","oversize") if k in snap})},args.daily_budget)
            saved={"after":previous,"generation":gen};state[endpoint]=saved
            # One earliest observed setup anchor per flow, including across pages.
            retained_flows = sorted(flow_anchors.values(), key=lambda a:a[3])[-1024:]
            state["audit_flow_anchors"] = retained_flows
            state["audit_legacy_anchors"] = legacy_anchors[-1024:]
            anchors = [list(a) for a in dict.fromkeys(tuple(a) for a in legacy_anchors + [[a[2],a[3]] for a in retained_flows])][-1024:]
            state["audit_anchors"]=anchors
            atomic_write(statepath,json.dumps(state).encode())
            summary["pages"]+=1;summary["records"]+=len(records)
            if len(records)<256:break
    if args.smartdns:
        key=read_key(args.key_file)
        text=ssh(args.smartdns,"tail -2000 /var/log/smartdns/smartdns-audit.log")
        tail=[e for line in text.splitlines() if (e:=parse(line,key))]
        by_site=collections.defaultdict(list)
        for site,at in anchors[-1024:]:by_site[site].append(at)
        seen=set(state.get("audit_recent_ids",[]))
        records=[]
        for e in tail:
            if e["id"] in seen:continue
            linked=any(0<=at-e["start_ms"]-e["duration_ms"]<=10000 for at in by_site[e["scope"]["site_id"]])
            empty_a=e["dns"]["qtype"]==1 and e["outcome"]=="empty_result"
            sampled=int(e["id"][-8:],16)%1000<25
            if linked or empty_a or sampled:records.append(e)
        if records:
            archive(records,args.output,{"endpoint":"smartdns_audit","host":"222","selection":"tail_2000_linked_10s_or_empty_A_or_hash_25_permille","timezone":"Asia/Shanghai","cross_host_clock_alignment":"unverified"},args.daily_budget)
        # Retain only archived IDs, so a later selected flow can still recover
        # its candidate from the overlapping tail. This is a bounded dedup set.
        retained=seen|{e["id"] for e in records}
        state["audit_recent_ids"]=[e["id"] for e in tail if e["id"] in retained]
        state["audit_anchors"]=anchors[-1024:]
        atomic_write(statepath,json.dumps(state).encode())
        summary["smartdns_tail_records"]=len(tail)
        summary["smartdns_records"]=len(records)
    summary["at"]=datetime.datetime.now(datetime.timezone.utc).isoformat()
    atomic_write(args.output/"latest-status.json",(json.dumps(summary,indent=2)+"\n").encode())
    print(json.dumps(summary))

if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--router",default="root@192.168.124.223")
    p.add_argument("--smartdns",default="root@192.168.124.222")
    p.add_argument("--key-file",type=Path,required=True)
    p.add_argument("--output",type=Path,required=True)
    p.add_argument("--max-pages",type=int,default=4)
    p.add_argument("--daily-budget",type=int,default=100<<20)
    run(p.parse_args())
