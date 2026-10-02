#!/usr/bin/env python3
"""Archive one bounded capture snapshot, never a raw admin/config dump.

Fetch input separately through authenticated admin access. Archives are immutable,
SHA-256 indexed and budget-limited. No network calls or automatic deletion here.
"""
import argparse
import datetime
import hashlib
import json
from pathlib import Path
from validate import audit, read_records
from archive_io import atomic_write


def archive(source, output, daily_limit=100 << 20):
    records, snapshot = read_records(source)
    report = audit(records)
    if not records:
        raise ValueError("empty snapshot: no evidence to archive")
    output.mkdir(parents=True, exist_ok=True, mode=0o700)
    day = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d")
    data = b"".join((json.dumps(r, separators=(",", ":")) + "\n").encode() for r in records)
    digest = hashlib.sha256(data).hexdigest()
    path = output / f"capture-{day}-{digest}.jsonl"
    report.update(artifact=path.name, artifact_sha256=digest, review="pending", gold=None,
                  snapshot_generation=snapshot.get("generation") if snapshot else None,
                  collector_stats=snapshot.get("stats") if snapshot else None,
                  oldest_sequence=snapshot.get("oldest_sequence") if snapshot else None,
                  next_sequence=snapshot.get("next_sequence") if snapshot else None)
    meta = path.with_suffix(".manifest.json")
    meta_data = (json.dumps(report, indent=2) + "\n").encode()
    if path.exists():
        if path.read_bytes() != data:
            raise ValueError("archive hash collision or corrupted artifact")
        if meta.exists():
            return path
    used = sum(p.stat().st_size for p in output.glob(f"capture-{day}-*"))
    if used + (0 if path.exists() else len(data)) + len(meta_data) > daily_limit:
        raise ValueError("daily archive budget exhausted; retain cursor and retry later")
    if not path.exists():
        atomic_write(path, data)
    atomic_write(meta, meta_data)
    return path


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    print(archive(args.input, args.output))
