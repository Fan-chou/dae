#!/usr/bin/env python3
"""Read-only, bounded collection for UDP recovery validation. No route edits."""
import argparse
import datetime as dt
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import time

SCHEMA = "kdae-udp-recovery-archive-v1"
META = r'''set -eu
pid=$(pidof dae)
case "$pid" in ''|*[!0-9]*) exit 3 ;; esac
binary=$(sha256sum "/proc/$pid/exe" | awk '{print $1}')
boot=$(cat /proc/sys/kernel/random/boot_id)
start=$(awk '{print $22}' "/proc/$pid/stat")
config=$(find /etc/dae -type f -name '*.dae' -exec sha256sum '{}' \; | sort | sha256sum | awk '{print $1}')
printf '{"pid":%s,"binary_sha256":"%s","boot_id":"%s","start_ticks":%s,"config_sha256":"%s"}\n' "$pid" "$binary" "$boot" "$start" "$config"
'''


def atomic_write(path, data):
    fd, name = tempfile.mkstemp(prefix="." + path.name + ".", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
        fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    finally:
        Path(name).unlink(missing_ok=True)


def encode(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def publish(output, value, budget):
    # Phase markers can arrive while the collector runs. Serialize their
    # budget checks and publication without taking the collector cursor lock.
    with (output / "archive.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        repair_archives_locked(output, budget)
        return publish_locked(output, value, budget)


def publish_locked(output, value, budget):
    data = encode(value)
    digest = hashlib.sha256(data).hexdigest()
    path = output / ("sample-" + digest + ".json")
    manifest = path.with_suffix(".manifest.json")
    meta = encode({"schema": SCHEMA, "sha256": digest, "bytes": len(data)})
    used = sum(p.stat().st_size for p in output.glob("*.json"))
    needed = (0 if path.exists() else len(data)) + (0 if manifest.exists() else len(meta))
    if used + needed > budget:
        raise ValueError("archive budget exhausted; cursor retained")
    if path.exists() and path.read_bytes() != data:
        raise ValueError("archive corruption; cursor retained")
    if manifest.exists() and manifest.read_bytes() != meta:
        raise ValueError("manifest corruption; cursor retained")
    # Publish the manifest first. Until the sample exists the analyzer ignores
    # it, so interruption cannot leave a new sample without its manifest.
    if not manifest.exists():
        atomic_write(manifest, meta)
    if not path.exists():
        atomic_write(path, data)
    return path


def repair_archives_locked(output, budget):
    # Older versions published complete samples first. Recover their immutable
    # manifest from verified bytes, independently of the next poll timestamp.
    used = sum(p.stat().st_size for p in output.glob("*.json"))
    for path in output.glob("sample-*.json"):
        if path.name.endswith(".manifest.json") or path.with_suffix(".manifest.json").exists():
            continue
        data = path.read_bytes()
        digest = hashlib.sha256(data).hexdigest()
        if path.name != "sample-" + digest + ".json" or json.loads(data).get("schema") != SCHEMA:
            raise ValueError("orphan archive corruption; cursor retained")
        meta = encode({"schema": SCHEMA, "sha256": digest, "bytes": len(data)})
        if used + len(meta) > budget:
            raise ValueError("archive budget exhausted during repair; cursor retained")
        atomic_write(path.with_suffix(".manifest.json"), meta)
        used += len(meta)


def ssh(router, command, text=None, timeout=20):
    if not router or router.startswith("-") or any(c.isspace() for c in router):
        raise ValueError("invalid SSH destination")
    result = subprocess.run(["ssh", "-oBatchMode=yes", "-oStrictHostKeyChecking=yes",
                             "-oConnectTimeout=5", router, command], input=text,
                            capture_output=True, text=True, timeout=timeout)
    if result.returncode:
        # Do not archive arbitrary SSH/remote stderr or configuration text.
        raise ValueError("SSH read failed, exit " + str(result.returncode))
    if len(result.stdout.encode()) > 4 * 1024 * 1024:
        raise ValueError("response exceeds 4 MiB")
    return json.loads(result.stdout)


def read_page(args, endpoint, after=0, process=""):
    start = time.time_ns() // 1_000_000
    command = "sh " + shlex.quote(args.reader) + " " + endpoint + " " + str(after)
    if process:
        command += " " + shlex.quote(process)
    page = ssh(args.router, command, timeout=read_timeout(args))
    end = time.time_ns() // 1_000_000
    bracket = {"endpoint": endpoint, "start_ms": start, "end_ms": end}
    if isinstance(page, dict) and type(page.get("at_ms")) is int:
        bracket["clock_offset_bounds_ms"] = [page["at_ms"] - end, page["at_ms"] - start]
    return page, bracket


def read_timeout(args):
    remaining = getattr(args, "deadline", float("inf")) - time.monotonic()
    if remaining <= 0:
        raise ValueError("collection deadline reached")
    return min(20, remaining)


def integer(value):
    return type(value) is int and value >= 0


def recovery_cursor(page, previous):
    if page.get("schema") != "kdae-udp-recovery-v1" or not page.get("process"):
        raise ValueError("UDP recovery channel unavailable or incompatible")
    if not isinstance(page.get("records"), list):
        raise ValueError("invalid recovery records")
    after = previous.get("after", 0)
    if page["process"] != previous.get("process") or page.get("cursor_reset"):
        after = 0
    for record in page["records"]:
        sequence = record.get("sequence")
        if not integer(sequence) or sequence <= after or not isinstance(record.get("kind"), str):
            raise ValueError("invalid recovery sequence")
        after = sequence
    if not integer(page.get("next_sequence")) or page["next_sequence"] != after:
        raise ValueError("recovery cursor does not match archived records")
    return {"process": page["process"], "after": after}


def capture_cursor(page, previous):
    if not page.get("enabled"):
        return previous
    after = previous.get("after", 0) if previous.get("generation") == page["generation"] else 0
    for record in page["records"]:
        if record.get("generation") != page["generation"] or not integer(record.get("sequence")) or record["sequence"] <= after:
            raise ValueError("invalid capture generation/sequence")
        after = record["sequence"]
    if page["next_sequence"] != after:
        raise ValueError("capture cursor does not match archived records")
    return {"generation": page["generation"], "after": after}


def collect_once(args, state):
    value = {"schema": SCHEMA, "kind": "poll", "router": args.router,
             "started_at_ms": time.time_ns() // 1_000_000,
             "pages": {}, "fetch_brackets": [], "errors": [], "gaps": []}
    cursors = dict(state)
    before = ssh(args.router, "sh -s", META, timeout=read_timeout(args))
    value["provenance_before"] = before
    for endpoint in ("udp-recovery", "capture", "status", "quality", "groups"):
        # Cumulative quality counters need no per-packet log collection.
        if endpoint in ("quality", "groups") and 0 <= value["started_at_ms"] - state.get("_aux_at_ms", 0) < 30000:
            continue
        saved = dict(cursors.get(endpoint, {}))
        try:
            for _ in range(args.max_pages if endpoint in ("capture", "udp-recovery") else 1):
                page, bracket = read_page(args, endpoint, saved.get("after", 0), saved.get("process", ""))
                value["fetch_brackets"].append(bracket)
                # Capture has no process-aware cursor. Re-fetch on a changed
                # generation even when its first page is empty.
                if endpoint == "capture" and page.get("enabled") and saved.get("generation") != page["generation"] and saved.get("after", 0):
                    value["gaps"].append({"endpoint": endpoint, "reason": "generation_changed"})
                    page, bracket = read_page(args, endpoint)
                    value["fetch_brackets"].append(bracket)
                value["pages"].setdefault(endpoint, []).append(page)
                if endpoint == "udp-recovery":
                    saved = recovery_cursor(page, saved)
                    if page.get("lost_records") or page.get("cursor_reset"):
                        value["gaps"].append({"endpoint": endpoint, "reason": page.get("cursor_reset", "ring_gap"), "lost_records": page.get("lost_records", 0)})
                    cursors[endpoint] = saved
                    if not page["has_more"]:
                        break
                elif endpoint == "capture":
                    if page.get("oldest_sequence", 0) > saved.get("after", 0) + 1:
                        value["gaps"].append({"endpoint": endpoint, "reason": "ring_gap", "oldest": page["oldest_sequence"]})
                    saved = capture_cursor(page, saved)
                    cursors[endpoint] = saved
                    if len(page.get("records", [])) < 256:
                        break
                else:
                    break
            else:
                value["gaps"].append({"endpoint": endpoint, "reason": "pagination_budget_reached"})
        except (ValueError, subprocess.TimeoutExpired, KeyError, TypeError) as error:
            value["errors"].append({"endpoint": endpoint, "error": str(error)})
    value["provenance_after"] = ssh(args.router, "sh -s", META, timeout=read_timeout(args))
    if "quality" in value["pages"] and "groups" in value["pages"]:
        cursors["_aux_at_ms"] = value["started_at_ms"]
    value["provenance_stable"] = before == value["provenance_after"]
    if not value["provenance_stable"]:
        value["gaps"].append({"reason": "process_binary_or_config_changed_during_poll"})
        cursors = state
    value["ended_at_ms"] = time.time_ns() // 1_000_000
    generations = set()
    for page in value["pages"].get("udp-recovery", []):
        generations.add(page.get("observation", {}).get("generation") if page.get("observation") else None)
    for page in value["pages"].get("status", []):
        generations.add(page.get("udp_reply_drought", {}).get("generation"))
    if len(generations) > 1:
        value["gaps"].append({"reason": "observation_generation_changed_during_poll"})
    # Publish complete data and hash manifest before advancing ANY cursor.
    publish(args.output, value, args.max_bytes)
    atomic_write(args.output / "cursor.json", encode(cursors))
    return cursors, value


def prepare_output(path):
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.is_symlink() or path.stat().st_mode & 0o077:
        raise ValueError("output must be a private directory (mode 0700)")


def collect(args):
    prepare_output(args.output)
    with (args.output / "collector.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        path = args.output / "cursor.json"
        state = json.loads(path.read_text()) if path.exists() else {}
        deadline = time.monotonic() + args.seconds
        args.deadline = deadline
        polls = 0
        while True:
            if polls and time.monotonic() >= deadline:
                break
            started = time.monotonic()
            try:
                state, value = collect_once(args, state)
            except (ValueError, subprocess.TimeoutExpired) as error:
                # A failed provenance read is still an explicit coverage gap.
                if "budget exhausted" in str(error) or "corruption" in str(error):
                    raise
                publish(args.output, {"schema": SCHEMA, "kind": "poll_failure",
                        "started_at_ms": time.time_ns() // 1_000_000, "error": str(error)}, args.max_bytes)
                value = {"errors": [str(error)]}
            polls += 1
            print(json.dumps({"poll": polls, "errors": len(value["errors"])}), flush=True)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            time.sleep(min(remaining, max(0, args.interval - (time.monotonic() - started))))


def mark(args):
    prepare_output(args.output)
    now = time.time_ns() // 1_000_000
    at = now
    if args.at:
        parsed = dt.datetime.fromisoformat(args.at.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            raise ValueError("--at requires an explicit UTC offset")
        at = int(parsed.timestamp() * 1000)
    if len(args.note) > 2048:
        raise ValueError("note exceeds 2048 characters")
    publish(args.output, {"schema": SCHEMA, "kind": "phase", "phase": args.phase,
            "event_at_ms": at, "reported_at_ms": now, "note": args.note,
            "timestamp_source": "operator_supplied" if args.at else "report_time"}, args.max_bytes)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for command in ("collect", "mark"):
        sub = commands.add_parser(command)
        sub.add_argument("--output", type=Path, required=True)
        sub.add_argument("--max-bytes", type=int, default=100 * 1024 * 1024)
        if command == "collect":
            sub.add_argument("--router", default="root@192.168.124.223")
            sub.add_argument("--reader", default="/usr/libexec/dae/read-observation.sh")
            sub.add_argument("--seconds", type=int, default=1200)
            sub.add_argument("--interval", type=float, default=5)
            sub.add_argument("--max-pages", type=int, default=4)
        else:
            sub.add_argument("--phase", choices=("lobby", "search", "playing", "paused", "ended", "error"), required=True)
            sub.add_argument("--at")
            sub.add_argument("--note", default="")
    args = parser.parse_args()
    if args.max_bytes <= 0:
        parser.error("--max-bytes must be positive")
    if args.command == "collect" and not (1 <= args.seconds <= 3600 and 1 <= args.interval <= 30 and 1 <= args.max_pages <= 8):
        parser.error("seconds: 1..3600, interval: 1..30, max-pages: 1..8")
    try:
        (collect if args.command == "collect" else mark)(args)
    except (ValueError, OSError, subprocess.TimeoutExpired) as error:
        print(str(error), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
