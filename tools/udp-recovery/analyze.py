#!/usr/bin/env python3
"""Verify archives and summarize evidence without inferring application semantics."""
import argparse
import collections
import hashlib
import json
from pathlib import Path
import sys

from collect import SCHEMA, encode


def load(output):
    values = []
    for path in sorted(output.glob("sample-*.json")):
        if path.name.endswith(".manifest.json"):
            continue
        data = path.read_bytes()
        digest = hashlib.sha256(data).hexdigest()
        if path.name != "sample-" + digest + ".json":
            raise ValueError("archive hash mismatch: " + path.name)
        meta = json.loads(path.with_suffix(".manifest.json").read_bytes())
        if meta != {"schema": SCHEMA, "sha256": digest, "bytes": len(data)}:
            raise ValueError("manifest mismatch: " + path.name)
        value = json.loads(data)
        if value.get("schema") != SCHEMA:
            raise ValueError("unknown archive schema")
        values.append(value)
    return sorted(values, key=lambda v: v.get("started_at_ms", v.get("event_at_ms", 0)))


def candidate_errors(row, thresholds):
    errors = []
    windows = row.get("windows", [])
    full = thresholds["required_full_buckets"]
    if len(windows) != full + 1:
        return ["window_count"]
    for i, w in enumerate(windows):
        if w["end_ms"] - w["start_ms"] != thresholds["bucket_ms"]:
            errors.append("bucket_duration")
        if i and w["start_ms"] != windows[i-1]["end_ms"]:
            errors.append("bucket_alignment")
        if i < full and (not w["complete"] or not w["present"] or w["invalid"] or w["nonempty_successful_writes"] < thresholds["nonempty_writes_per_bucket"]):
            errors.append("insufficient_full_bucket")
    if windows[-1]["complete"] or windows[-1]["invalid"]:
        errors.append("current_bucket")
    start = windows[0]["start_ms"]
    if row["first_observed_ms"] > start or row.get("invalidated_at_ms", 0) >= start:
        errors.append("incomplete_history")
    if row["replies"] < thresholds["required_reply_history"]:
        errors.append("reply_history")
    if row["last_reply_ms"] > start or row["at_ms"] - row["last_reply_ms"] < thresholds["reply_drought_ms"]:
        errors.append("recent_reply")
    if not 0 <= row["at_ms"] - row["last_write_ms"] <= thresholds["recent_write_ms"]:
        errors.append("paused_or_clock_uncertain")
    if row["write_completion"] != "local_write_completed":
        errors.append("write_completion")
    if row["reply_contract"] != "configured_request_reply":
        errors.append("unknown_reply_semantics")
    return errors


def ratio(n, d):
    return n / d if d else None


def summarize(values):
    events, peers, captures, associations = {}, {}, {}, {}
    observations, capture_stats, budgets, budget_history = {}, {}, {}, {}
    missing = {}
    gaps, errors, phases, invalid_candidates = [], [], [], []
    polls, offsets = [], []
    execution_available = False
    budget_channel_available = False
    for value in values:
        kind = value["kind"]
        if kind == "phase":
            phases.append(value)
            continue
        if kind == "poll_failure":
            errors.append(value)
            continue
        polls.append(value)
        gaps.extend(value["gaps"])
        errors.extend(value["errors"])
        offsets.extend(b for b in value["fetch_brackets"] if "clock_offset_bounds_ms" in b)
        if not value["provenance_stable"]:
            continue  # Preserve raw data, exclude it from validated outcomes.
        for page in value["pages"].get("udp-recovery", []):
            process = page["process"]
            execution_available |= page["execution_implemented"]
            observation = page.get("observation")
            if observation:
                observations[(process, observation["generation"])] = observation
                for row in observation["peers"]:
                    key = (process, observation["generation"], row["association"], row["peer"])
                    previous = peers.get(key)
                    if previous is None or row["successful_writes"] >= previous["successful_writes"]:
                        peers[key] = row
                for row in observation.get("associations", []):
                    associations[(process, observation["generation"], row["association"])] = row
            if page["coverage"]["truncated"] or page["coverage"]["missing_events_dedup_full"]:
                gaps.append({"reason": "coverage_capacity_reached", "process": process})
            for row in page["coverage"]["flows"]:
                if row["state"] != "observed":
                    missing[(process, row["runtime_id"], row["state"])] = row
            for e in page["records"]:
                key = (process, e["sequence"])
                if key in events and encode(events[key]) != encode(e):
                    raise ValueError("event identity reused with different evidence")
                events[key] = e
                if e.get("association"):
                    a = e["association"]
                    akey = (process, e["generation"], a["association"])
                    previous = associations.get(akey)
                    if previous is None or a["unattributed_writes"] + a["unattributed_replies"] >= previous["unattributed_writes"] + previous["unattributed_replies"]:
                        associations[akey] = a
                row = e.get("peer")
                if row:
                    pkey = (process, e["generation"], row["association"], row["peer"])
                    if pkey not in peers or row["successful_writes"] >= peers[pkey]["successful_writes"]:
                        peers[pkey] = row
                    if e["kind"] == "qualified":
                        failures = candidate_errors(row, page["thresholds"])
                        if failures:
                            invalid_candidates.append({"process": process, "sequence": e["sequence"], "errors": failures})
        for page in value["pages"].get("capture", []):
            if not page.get("enabled"):
                continue
            gen = page["generation"]
            capture_stats[gen] = page["stats"]
            for r in page["records"]:
                key = (gen, r["sequence"])
                if key in captures and encode(captures[key]) != encode(r):
                    raise ValueError("capture identity reused with different evidence")
                captures[key] = r
        for page in value["pages"].get("quality", []):
            budget_channel_available |= "recovery_diagnostics" in page
            for g in page.get("recovery_diagnostics", []):
                # A poll preserves all raw values. The overview is the latest
                # group state; it does not claim continuity across reload.
                budgets[g["group"]] = g
                bkey = (value["provenance_before"].get("boot_id"), value["provenance_before"].get("start_ticks"), g["policy_epoch"], g["group"])
                if bkey not in budget_history:
                    budget_history[bkey] = {"policy_epoch": g["policy_epoch"], "group": g["group"], "first_at_ms": value["started_at_ms"], "first": g}
                budget_history[bkey].update(last_at_ms=value["started_at_ms"], last=g)
    for previous, current in zip(polls, polls[1:]):
        if current["started_at_ms"] - previous["started_at_ms"] > 10_000:
            gaps.append({"reason": "poll_interval_over_10s", "after_ms": previous["started_at_ms"], "before_ms": current["started_at_ms"]})
    counts = collections.Counter(e["kind"] for e in events.values())
    for h in budget_history.values():
        before, after = h.pop("first"), h["last"]
        seconds = (h["last_at_ms"] - h["first_at_ms"]) / 1000
        h["quality_reason_counter_delta"] = {k: n - before["quality_reasons"].get(k, 0) for k, n in after["quality_reasons"].items()}
        h["verification_windows_per_minute"] = ratio(h["quality_reason_counter_delta"].get("verify_alternative_windows", 0) * 60, seconds)
    endings = collections.Counter(e.get("reason", "") for e in events.values() if e["kind"] == "candidate_ended")
    byte_comparison = []
    byte_skew_excluded = 0
    relay_by_gen = collections.Counter()
    offload_by_gen = collections.Counter()
    for (gen, _), r in captures.items():
        if r["stage"] != "relay":
            continue
        relay_by_gen[gen] += 1
        offload_by_gen[gen] += r["measurement_mode"] == "offload_or_unmeasured"
        byte_skew_excluded += r.get("missing_reason", {}).get("node_bytes") == "counter_reset_or_snapshot_skew"
        if all(r.get(k) is not None for k in ("up_bytes", "down_bytes", "node_up_bytes", "node_down_bytes")):
            byte_comparison.append({"generation": gen, "sequence": r["sequence"],
                    "node_minus_flow_up": r["node_up_bytes"] - r["up_bytes"],
                    "node_minus_flow_down": r["node_down_bytes"] - r["down_bytes"],
                    "alignment": r["counter_alignment"]})
    capture_summary = []
    for gen, stats in capture_stats.items():
        exported = sum(k[0] == gen for k in captures)
        capture_summary.append({"generation": gen, "stats_last_seen": stats,
                "relay_windows_archived": relay_by_gen[gen],
                "offload_fraction_of_archived_relay_windows": ratio(offload_by_gen[gen], relay_by_gen[gen]),
                "queue_drop_fraction_of_observed_submissions": ratio(stats["queue_dropped"], exported + stats["queue_dropped"]),
                "invalid_events_per_archived_relay_window": ratio(stats["invalid_window"], relay_by_gen[gen]),
                "denominators_are_archive_lower_bounds": True})
    return {"schema": "kdae-udp-recovery-summary-v1", "polls": len(polls),
            "provenance": [p["provenance_before"] for p in polls[:1]],
            "phase_markers": phases, "clock_offset_brackets": offsets,
            "gaps": gaps, "errors": errors, "coverage_missing_or_incomplete": list(missing.values()),
            "candidate_events_archived": counts["qualified"], "candidate_end_reasons": dict(endings),
            "candidate_evidence_validation": "failed" if invalid_candidates else ("passed_for_archived_candidates" if counts["qualified"] else "no_candidates_observed"),
            "invalid_candidate_evidence": invalid_candidates, "event_counts_archived": dict(counts),
            "observer_stats_last_seen_by_generation": [{"process": p, "generation": g, "contract": o["contract"], "stats": o["stats"], "excluded": o["excluded"]} for (p, g), o in observations.items()],
            "observed_peer_records": len(peers), "successful_writes_last_seen_lower_bound": sum(r["successful_writes"] for r in peers.values()),
            "associations_with_unattributed_observations": [dict(a, process=p, generation=g) for (p, g, _), a in associations.items() if a["unattributed_writes"] or a["unattributed_replies"]],
            "valid_replies_last_seen_lower_bound": sum(r["replies"] for r in peers.values()),
            "capture": capture_summary, "node_flow_comparable_windows": len(byte_comparison),
            "node_flow_counter_differences": byte_comparison, "quality_budgets_last_seen": list(budgets.values()),
            "node_flow_skew_excluded_windows": byte_skew_excluded,
            "quality_budget_channel_available": budget_channel_available,
            "quality_budget_history_by_generation": list(budget_history.values()),
            "execution_implemented": execution_available,
            "execution_acceptance": "not_evaluated", "application_acceptance": "requires_operator_result",
            "limitations": ["Unknown application reply obligations remain excluded.",
                "Node counters include concurrent flows; positive difference is not measurement error.",
                "Unmeasured splice flows have no flow-byte reference; exact bias cannot be computed.",
                "No candidate or no archived event is not evidence of full coverage or successful recovery."]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    try:
        summary = summarize(load(args.output))
        print(json.dumps(summary, ensure_ascii=False, indent=2))
        return 2 if summary["invalid_candidate_evidence"] else 0
    except (ValueError, OSError, KeyError, TypeError) as error:
        print(str(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
