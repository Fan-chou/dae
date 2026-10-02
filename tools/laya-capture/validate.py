#!/usr/bin/env python3
"""Validate passive capture, report missingness, and refuse unsupported V4 input.

Accept JSONL records or one authenticated /v1/capture JSON snapshot. No model,
network, oracle labels or data imputation. Counts are NOT root-cause counts.
"""
import argparse
import collections
import hashlib
import json
import math
from pathlib import Path
import re

SCHEMA = "kdae-capture-v1"
MISSING_KEYS = {"control", "dependency", "demand", "active_ms", "read_paused_ms", "node_bytes", "flow_bytes"}
KEYS = {"schema", "generation", "id", "episode_id", "sequence", "scope", "start_ms", "duration_ms", "partial", "measurement_mode", "stage", "outcome", "up_bytes", "down_bytes", "node_up_bytes", "node_down_bytes", "active_ms", "read_paused_ms", "control", "dependency", "demand", "missing_reason", "inclusion_probability", "trigger", "counter_alignment", "adapter_status", "first_downstream_callback_ms"}


def integer(value, name, minimum=0):
    if type(value) is not int or value < minimum:
        raise ValueError(f"{name}: expected integer >= {minimum}")


# UTC year 9999 is the largest supported archive timestamp; reject unit errors
# and values that datetime-based downstream tools cannot represent.
MAX_TIMESTAMP_MS = 253402300799999

def validate_time(record):
    if record["start_ms"] > MAX_TIMESTAMP_MS or record["start_ms"] + record["duration_ms"] > MAX_TIMESTAMP_MS:
        raise ValueError("timestamp outside supported millisecond range")


def validate(record):
    if not isinstance(record, dict) or set(record) != KEYS:
        raise ValueError("record fields differ from capture-v1 (unknown fields may leak private data)")
    if record["schema"] != SCHEMA or record["adapter_status"] != "adapter_abstain":
        raise ValueError("unsupported capture schema or unsupported model acceptance")
    for key in ("sequence", "start_ms", "duration_ms"):
        integer(record[key], key, 1 if key in ("sequence", "start_ms") else 0)
    validate_time(record)
    if type(record["partial"]) is not bool:
        raise ValueError("partial must be boolean")
    for key in ("generation", "id", "episode_id"):
        if not isinstance(record[key], str) or not re.fullmatch(r"[a-zA-Z0-9-]{1,160}", record[key]):
            raise ValueError(f"invalid opaque {key}")
    scope = record["scope"]
    if not isinstance(scope, dict) or set(scope) != {"site_id", "node_id", "group_id", "network", "path", "policy_epoch"}:
        raise ValueError("invalid scope fields")
    for key in ("site_id", "node_id", "group_id"):
        if not isinstance(scope[key], str) or not re.fullmatch(r"(?:[0-9a-f]{32})?", scope[key]):
            raise ValueError("scope identity must be opaque or explicitly empty")
    if scope["network"] not in ("unknown", "tcp4", "tcp6", "tcp", "tcp(4)", "tcp(6)") or scope["path"] not in ("unknown", "direct", "proxy"):
        raise ValueError("unsupported scope")
    integer(scope["policy_epoch"], "policy_epoch")
    p = record["inclusion_probability"]
    if type(p) not in (int, float) or not math.isfinite(p) or not 0 < p <= 1:
        raise ValueError("invalid sampling probability")
    if record["trigger"] not in ("uniform_flow", "uniform_route"):
        raise ValueError("unsupported sampling trigger")
    missing = record["missing_reason"]
    if not isinstance(missing, dict) or set(missing) != MISSING_KEYS:
        raise ValueError("missing-reason fields differ")
    for reason in missing.values():
        if not isinstance(reason, str) or not re.fullmatch(r"[a-z_]*", reason):
            raise ValueError("invalid missing reason")
    # v1 intentionally does not instrument application demand or dependency
    # controls. A later enriched schema must be versioned and reviewed.
    for key in ("control", "dependency", "demand", "active_ms", "read_paused_ms"):
        if record[key] is not None or not missing[key]:
            raise ValueError(f"{key}: capture-v1 cannot claim measured evidence")
    for keys, reason in ((('up_bytes', 'down_bytes'), 'flow_bytes'), (('node_up_bytes', 'node_down_bytes'), 'node_bytes')):
        values = [record[key] for key in keys]
        if any(value is None for value in values):
            if not all(value is None for value in values) or not missing[reason]:
                raise ValueError("partial counter pair or missing provenance")
        else:
            for key in keys:
                integer(record[key], key)
            if missing[reason]:
                raise ValueError("measured counter also marked missing")
    if record["first_downstream_callback_ms"] is not None:
        integer(record["first_downstream_callback_ms"], "first_downstream_callback_ms")
    mode = record["measurement_mode"]
    if mode not in ("userspace_accounting", "offload_or_unmeasured", "stage_only"):
        raise ValueError("unsupported measurement mode")
    if mode != "userspace_accounting" and any(record[k] is not None for k in ("up_bytes", "down_bytes", "node_up_bytes", "node_down_bytes")):
        raise ValueError("unmeasured flow claims byte evidence")
    if record["stage"] not in ("relay", "route_resolve_dial") or record["outcome"] not in ("open", "relay_ended", "relay_error", "offload_error", "adopt_abandoned", "canceled", "success", "route_error"):
        raise ValueError("unsupported stage or outcome")
    if record["counter_alignment"] not in ("best_effort_non_atomic_snapshots", "not_applicable"):
        raise ValueError("unsupported alignment")
    route = record["stage"] == "route_resolve_dial"
    if route:
        if mode != "stage_only" or record["trigger"] != "uniform_route" or record["counter_alignment"] != "not_applicable" or not record["partial"] or record["outcome"] not in {"success", "route_error", "canceled"}:
            raise ValueError("route stage/provenance mismatch")
    elif mode == "stage_only" or record["trigger"] != "uniform_flow" or record["counter_alignment"] != "best_effort_non_atomic_snapshots" or record["outcome"] in {"success", "route_error"}:
        raise ValueError("relay stage/provenance mismatch")
    if record["node_up_bytes"] is not None and record["up_bytes"] is not None:
        if record["node_up_bytes"] < record["up_bytes"] or record["node_down_bytes"] < record["down_bytes"]:
            raise ValueError("node counter smaller than flow counter")
    if len(json.dumps(record, separators=(",", ":")).encode()) > 16384:
        raise ValueError("record exceeds 16 KiB")


def read_records(path):
    text = Path(path).read_text()
    try:
        obj = json.loads(text)
    except json.JSONDecodeError:
        return [json.loads(line) for line in text.splitlines() if line.strip()], None
    if isinstance(obj, dict) and "records" in obj:
        return obj["records"], obj
    return [obj], None


def audit(records):
    missing = collections.Counter()
    stages = collections.Counter()
    ids, episodes, generations = set(), set(), set()
    missing_by_stage = collections.defaultdict(collections.Counter)
    for record in records:
        validate(record)
        key = (record["generation"], record["id"])
        if key in ids:
            raise ValueError("duplicate record (deduplicate overlapping snapshots before audit)")
        ids.add(key)
        episodes.add((record["generation"], record["episode_id"]))
        generations.add(record["generation"])
        stages[record["stage"]] += 1
        missing.update(k for k, v in record["missing_reason"].items() if v)
        missing_by_stage[record["stage"]].update(k for k, v in record["missing_reason"].items() if v)
    return {"records": len(records), "provisional_episodes": len(episodes), "root_cause_independence": "unreviewed", "generations": len(generations), "stages": dict(stages), "missing_counts": dict(missing), "missing_rates": {k: v / len(records) for k, v in missing.items()} if records else {}, "missing_rates_by_stage": {stage: {k: v / stages[stage] for k, v in counts.items()} for stage, counts in missing_by_stage.items()}, "v4_adapter_accepted": 0, "v4_adapter_abstained": len(records), "gold_status": "unlabeled"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    records, snapshot = read_records(args.input)
    report = audit(records)
    report["artifact_sha256"] = hashlib.sha256(args.input.read_bytes()).hexdigest()
    if snapshot:
        report["collector_stats"] = snapshot.get("stats")
        report["oldest_sequence"] = snapshot.get("oldest_sequence")
        report["next_sequence"] = snapshot.get("next_sequence")
    text = json.dumps(report, indent=2, ensure_ascii=False) + "\n"
    if args.output:
        args.output.write_text(text)
    else:
        print(text, end="")


if __name__ == "__main__":
    main()
