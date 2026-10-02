#!/usr/bin/env python3
"""Validate human review records; never generate labels from a model or rules."""
import argparse
import json
import unicodedata
from pathlib import Path

TASKS={"node_fault","demand_shortfall","recovery"}
LABELS={"supported","contradicted","unknown"}

def reviewer_identity(name):
    if not isinstance(name, str):
        raise ValueError("reviewer name must be text")
    return " ".join(unicodedata.normalize("NFKC", name).casefold().split())


def validate(review, annotations):
    episodes={(e["generation"],e["flow_id"]):e for e in review["episodes"]}
    seen=set()
    for a in annotations:
        if set(a)!={"generation","flow_id","incident_id","split","reviews"}:raise ValueError("invalid annotation fields")
        key=(a["generation"],a["flow_id"])
        if key not in episodes or key in seen:raise ValueError("unknown/duplicate flow")
        seen.add(key);ep=episodes[key]
        if not isinstance(a["incident_id"],str) or not a["incident_id"].strip():raise ValueError("root-cause clustering required")
        if a["split"] not in {"development","train","calibration_fit","policy_select","final_test"}:raise ValueError("invalid split")
        rs=a["reviews"]
        if len(rs)!=2 or len({reviewer_identity(r["reviewer"]) for r in rs})!=2:raise ValueError("two distinct independent human reviews required")
        # Follow-up evidence may explain retrospective root cause but is not
        # valid decision-time evidence for the three model tasks.
        valid=set(ep["input_event_ids"]+ep["capture_record_ids"])
        valid.update(r["event_id"] for r in ep["dns_candidates"]+ep.get("dns_upstream_candidates",[])+ep["control_candidates"])
        for r in rs:
            if set(r)!={"reviewer","model_blind","tasks"} or not reviewer_identity(r["reviewer"]) or r["model_blind"] is not True:raise ValueError("review provenance missing")
            if set(r["tasks"])!=TASKS:raise ValueError("three tasks required")
            for task,v in r["tasks"].items():
                if set(v)!={"label","evidence_ids","rationale"} or v["label"] not in LABELS:raise ValueError("invalid task annotation")
                if not isinstance(v["rationale"],str) or not v["rationale"].strip():raise ValueError("rationale required")
                if not isinstance(v["evidence_ids"],list) or not set(v["evidence_ids"])<=valid:raise ValueError("future/unknown evidence in decision label")
                if v["label"]!="unknown" and not v["evidence_ids"]:raise ValueError("supported/contradicted requires citations")
        if any(rs[0]["tasks"][t]["label"]!=rs[1]["tasks"][t]["label"] for t in TASKS):raise ValueError("review disagreement unresolved; not training-ready")
    by_incident={}
    for a in annotations:
        previous=by_incident.setdefault(a["incident_id"],a["split"])
        if previous!=a["split"]:raise ValueError("root-cause cluster leaks across splits")
    return {"reviewed_flows":len(seen),"independent_incidents":len(by_incident),"status":"review_structure_valid_not_v4_ready"}

if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__);p.add_argument("bundle",type=Path);p.add_argument("annotations",nargs="+",type=Path);a=p.parse_args()
    print(json.dumps(validate(json.loads(a.bundle.read_text()),[record for path in a.annotations for record in json.loads(path.read_text())])))
