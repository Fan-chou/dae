#!/usr/bin/env python3
"""Strict evidence validation and conservative, time-bounded review bundles.

No inferred demand, automatic root-cause gold, or production model inputs.
"""
import argparse
import collections
import hashlib
import json
import math
import re
from pathlib import Path
from validate import integer, validate_time, read_records, validate as validate_capture

SCHEMA = "kdae-evidence-events-v1"
KEYS = set("schema generation sequence id flow_id capture_episode_id kind scope target_id target_kind client_id start_ms duration_ms outcome dns load inclusion_probability source sampling_frame".split())
KINDS = {"selection_resolution", "dial", "flow_link", "relay_end", "load_window", "dns_upstream", "dns_client_reply", "dns_cache_hit", "smartdns_audit"}
OPAQUE = re.compile(r"[a-zA-Z0-9-]{1,160}\Z")
HASH = re.compile(r"(?:[0-9a-f]{32})?\Z")

def require(condition, message):
    if not condition:
        raise ValueError(message)

def validate(e):
    require(isinstance(e, dict) and set(e) in (KEYS, KEYS | {"error_facts"}), "unknown/missing evidence fields")
    require(e["schema"] == SCHEMA and e["kind"] in KINDS, "unsupported schema/kind")
    for k in ("id", "generation", "flow_id"):
        require(isinstance(e[k], str) and OPAQUE.fullmatch(e[k]), "invalid opaque identity")
    require(e["capture_episode_id"] == "" or (isinstance(e["capture_episode_id"], str) and OPAQUE.fullmatch(e["capture_episode_id"])), "invalid capture identity")
    for k in ("sequence", "start_ms", "duration_ms"):
        integer(e[k], k, 0 if k == "duration_ms" else 1)
    validate_time(e)
    scope = e["scope"]
    require(isinstance(scope, dict) and set(scope) == set("site_id node_id group_id network path policy_epoch".split()), "invalid scope")
    for v in [scope[k] for k in ("site_id", "node_id", "group_id")] + [e["target_id"], e["client_id"]]:
        require(isinstance(v, str) and HASH.fullmatch(v), "raw identity rejected")
    integer(scope["policy_epoch"], "policy_epoch")
    require(scope["network"] in {"unknown", "dns", "tcp", "tcp4", "tcp6", "tcp(4)", "tcp(6)"}, "invalid network")
    require(scope["path"] in {"unknown", "direct", "proxy"}, "invalid path")
    require(e["target_kind"] in {"", "unknown", "ip", "name"}, "invalid target kind")
    require(e["outcome"] in {"success", "unmeasured", "error", "timeout", "canceled", "open", "relay_ended", "relay_error", "offload_error", "adopt_abandoned", "recorded", "empty_result"}, "invalid outcome")
    if e["source"] == "smartdns-222":
        require(e["kind"] == "smartdns_audit" and e["sampling_frame"] == "audit_tail" and e["inclusion_probability"] is None, "audit tail is not representative sampling")
    else:
        require(e["source"] == "kdae" and e["kind"] != "smartdns_audit" and e["sampling_frame"] == ("uniform_dns_event" if e["kind"].startswith("dns_") else "uniform_trace"), "invalid source/sampling frame")
        p = e["inclusion_probability"]
        require(type(p) in (int, float) and math.isfinite(p) and 0 < p <= 1, "invalid probability")
    if "error_facts" in e:
        f = e["error_facts"]
        require(isinstance(f, dict) and set(f) == {"class", "stage"}, "invalid error facts")
        require(f["class"] in {"none", "canceled", "timeout", "connection_reset", "connection_refused", "network_unreachable", "host_unreachable", "broken_pipe", "closed", "unknown"}, "raw/unknown error class")
        stages = {"dial": {"dial"}, "selection_resolution": {"selection_resolution"}, "relay_end": {"adopt", "relay", "offload"}}
        require(f["stage"] in stages.get(e["kind"], set()), "error stage mismatch")
    dns = e["dns"]
    dns_kind = e["kind"].startswith("dns_") or e["kind"] == "smartdns_audit"
    require((dns is not None) == dns_kind, "DNS kind/facts mismatch")
    if dns is not None:
        require(isinstance(dns, dict) and set(dns) == set("qtype rcode answer_ips fake_ips truncated cache_status filter_reason upstream_id answer_ids".split()), "unknown DNS fields")
        for k in ("qtype", "answer_ips", "fake_ips"):
            integer(dns[k], k)
        require(dns["qtype"] <= 65535 and dns["fake_ips"] <= dns["answer_ips"], "invalid DNS counts")
        if dns["rcode"] is not None:
            integer(dns["rcode"], "rcode")
            require(dns["rcode"] <= 4095, "invalid rcode")
        require(dns["truncated"] is None or type(dns["truncated"]) is bool, "invalid TC bit")
        require(dns["cache_status"] in {"unknown", "not_applicable", "hit", "stale_hit"}, "invented cache state")
        require(dns["filter_reason"] == "unobserved", "filter attribution requires separate evidence")
        require(isinstance(dns["upstream_id"], str) and HASH.fullmatch(dns["upstream_id"]), "raw upstream rejected")
        require(isinstance(dns["answer_ids"], list) and len(dns["answer_ids"]) <= min(32, dns["answer_ips"]), "invalid answers")
        require(all(isinstance(v, str) and re.fullmatch(r"[0-9a-f]{32}", v) for v in dns["answer_ids"]), "raw IP rejected")
        if e["outcome"] in {"canceled", "timeout", "error"}:
            require(dns["rcode"] is None and dns["answer_ips"] == 0, "transport failure claims DNS response")
    load = e["load"]
    require((load is not None) == (e["kind"] == "load_window"), "load kind/facts mismatch")
    if load is not None:
        require(isinstance(load, dict) and set(load) == set("own_up_bytes own_down_bytes other_up_bytes other_down_bytes active_connections_at_snapshot starts_total_at_snapshot alignment missing_reason".split()), "unknown load fields")
        for k in ("own_up_bytes", "own_down_bytes", "other_up_bytes", "other_down_bytes", "active_connections_at_snapshot", "starts_total_at_snapshot"):
            if load[k] is not None:
                integer(load[k], k)
        for a,b in (("own_up_bytes","own_down_bytes"),("other_up_bytes","other_down_bytes")):
            require((load[a] is None) == (load[b] is None), "partial counter pair")
        require(load["alignment"] == "best_effort_non_atomic_snapshots", "overclaimed alignment")
        require(isinstance(load["missing_reason"], str) and re.fullmatch(r"[a-z_]*",load["missing_reason"]), "invalid missing reason")
        require((load["other_up_bytes"] is None) == bool(load["missing_reason"]), "missing load provenance")
        require(load["other_up_bytes"] is None or load["own_up_bytes"] is not None, "other bytes without own counters")
    require(len(json.dumps(e).encode()) <= 16384, "record too large")

def load(paths, capture=False):
    records, seen = [], {}
    for path in paths:
        rs, _ = read_records(path)
        for r in rs:
            (validate_capture if capture else validate)(r)
            key = (r["generation"],r["id"])
            if key in seen:
                require(seen[key] == r, "conflicting duplicate evidence")
                continue
            seen[key] = r
            records.append(r)
    return sorted(records, key=lambda r: (r["start_ms"],r["sequence"]))

def end(e):
    return e["start_ms"] + e["duration_ms"]

def bundle(events, captures=(), tolerance_ms=10000):
    for e in events:
        validate(e)
    flows = collections.defaultdict(list)
    dns = collections.defaultdict(list)
    dials = []
    for e in events:
        if e["dns"] is not None:
            dns[e["scope"]["site_id"]].append(e)
        else:
            flows[(e["generation"], e["flow_id"])].append(e)
            if e["kind"] == "dial":
                dials.append(e)
    capture_by_id = collections.defaultdict(list)
    for r in captures:
        validate_capture(r)
        capture_by_id[(r["generation"],r["episode_id"])].append(r)
    episodes = []
    for (generation, flow), rs in flows.items():
        # First observed closed window, or first dial outcome if there is none.
        anchors = [r for r in rs if r["kind"] == "load_window"] or [r for r in rs if r["kind"] == "dial"] or rs
        anchor = min(anchors, key=end)
        decision = end(anchor)
        inputs = [r for r in rs if end(r) <= decision]
        followups = [r for r in rs if end(r) > decision]
        site = anchor["scope"]["site_id"]
        flow_client = next((r["client_id"] for r in inputs if r["client_id"]), "")
        # DNS belongs to connection setup; the decision may occur much later
        # when the first load window closes. Never include future DNS replies.
        connection_start = min(r["start_ms"] for r in rs)
        candidates = [r for r in dns.get(site, []) if site and r["kind"] != "dns_upstream"
                      and 0 <= connection_start-end(r) <= tolerance_ms]
        upstreams = [r for r in dns.get(site, []) if site and r["kind"] == "dns_upstream"
                     and connection_start-tolerance_ms <= r["start_ms"] and end(r) <= decision]
        controls = []
        for a in [r for r in inputs if r["kind"] == "dial"]:
            for b in dials:
                if b["generation"] != generation or b["flow_id"] == flow or end(b)>decision:
                    continue
                sa,sb = a["scope"],b["scope"]
                if not sa["node_id"] or not sb["node_id"] or sa["node_id"] == sb["node_id"]:
                    continue
                if sa["network"] != sb["network"] or sa["policy_epoch"] != sb["policy_epoch"]:
                    continue
                if not a["target_id"] or a["target_id"] != b["target_id"] or abs(end(a)-end(b))>tolerance_ms:
                    continue
                # Even equal destination IPs do not establish equal application requests.
                controls.append({"event_id":b["id"],"strength":"same_ip_candidate" if a["target_kind"] == b["target_kind"] == "ip" else "same_name_candidate", "outcome":b["outcome"]})
        captures_here=[]
        for capture_id in {r["capture_episode_id"] for r in inputs if r["capture_episode_id"]}:
            captures_here.extend(r for r in capture_by_id.get((generation,capture_id),[]) if end(r)<=decision)
        episodes.append({"flow_id":flow,"generation":generation,"decision_ms":decision,
            "input_event_ids":[r["id"] for r in inputs],"capture_record_ids":[r["id"] for r in captures_here],
            "followup_event_ids_not_model_input":[r["id"] for r in followups],
            "dns_candidates":[{"event_id":r["id"],"strength":"same_client_site_time_candidate" if r["client_id"] and r["client_id"] == flow_client else "site_time_only_candidate"} for r in candidates],
            "dns_upstream_candidates":[{"event_id":r["id"],"strength":"kdae_upstream_site_time_candidate"} for r in upstreams],
            "control_candidates":controls,"incident_id":None,"review":"pending","gold":None,
            "adapter_status":"adapter_abstain","missing":["application_demand","application_read_backpressure","independent_control_review","root_cause_review"],
            "reviewers":[],"disposition":"research_only"})
    return {"schema":"kdae-evidence-review-v1","events":len(events),"provisional_flows":len(episodes),"independent_incidents":None,
        "candidate_tolerance_ms":tolerance_ms,"cross_host_clock_alignment":"unverified_candidates_only",
        "v4_accepted":0,"episodes":episodes}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("events",nargs="+",type=Path);p.add_argument("--captures",nargs="*",type=Path,default=[]);p.add_argument("--output",type=Path,required=True)
    a=p.parse_args();events=load(a.events);result=bundle(events,load(a.captures,True))
    result["sources"]=[{"file":str(f),"sha256":hashlib.sha256(f.read_bytes()).hexdigest()} for f in a.events+a.captures]
    a.output.write_text(json.dumps(result,indent=2)+"\n");a.output.chmod(0o600)
    print(json.dumps({k:v for k,v in result.items() if k not in {"episodes","sources"}}))
if __name__=="__main__":main()
