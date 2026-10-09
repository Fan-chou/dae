#!/usr/bin/env python3
"""Cross-check the rule fixtures against a real Mihomo binary.

    MIHOMO_BIN=/path/to/mihomo ./crosscheck_mihomo.py
    # Compare with this converter as well as the archived sidecar:
    DUMP_ACCEPTANCE=/tmp/ours.json go test ./component/mihomo -run TestDumpAcceptance
    MIHOMO_BIN=... OURS=/tmp/ours.json ./crosscheck_mihomo.py

Mihomo is the reference for what a configuration means; the archived sidecar
is only the reference for what the converter used to do. For every fixture in
testdata/rules/cases.yaml this runs `mihomo -t` and lists where Mihomo and
the sidecar disagree about accepting the rules. Disagreements are expected
(the sidecar is more lenient about things Mihomo never loads, stricter about
things it does not model); the list is for review, not a pass/fail gate.
"""
import json
import os
import subprocess
import sys
import tempfile

import yaml

here = os.path.dirname(os.path.abspath(__file__))
mihomo = os.environ.get("MIHOMO_BIN")
if not mihomo or not os.access(mihomo, os.X_OK):
    sys.exit("set MIHOMO_BIN to a mihomo binary")

data = os.path.join(here, "..", "..", "component", "mihomo", "testdata", "rules")
cases = yaml.safe_load(open(os.path.join(data, "cases.yaml")))["cases"]
golden = json.load(open(os.path.join(data, "golden.json")))

ours = json.load(open(os.environ["OURS"])) if os.environ.get("OURS") else None
rows = []
for name, case in cases.items():
    rules = list(case["rules"]) + ([] if case.get("no_match") else ["MATCH,PROXY"])
    doc = {
        "mixed-port": 7890,
        "proxies": [{"name": "n1", "type": "socks5", "server": "127.0.0.1", "port": 1080}],
        "proxy-groups": [
            {"name": "PROXY", "type": "select", "proxies": ["n1", "DIRECT"]},
            {"name": "OTHER", "type": "select", "proxies": ["n1"]},
        ],
        "rules": rules,
    }
    if case.get("sub_rules"):
        doc["sub-rules"] = case["sub_rules"]
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "c.yaml")
        with open(path, "w") as f:
            yaml.safe_dump(doc, f, allow_unicode=True, width=10**6, default_flow_style=False)
        res = subprocess.run([mihomo, "-t", "-d", tmp, "-f", path], capture_output=True, text=True)
    error = ""
    if res.returncode != 0:
        for line in (res.stdout + res.stderr).splitlines():
            if "level=error" in line:
                error = line.split("msg=")[-1][:150]
                break
    rows.append((name, res.returncode == 0, golden[name]["ok"], error))

print("Mihomo rejects, sidecar converts:")
for name, m, o, e in rows:
    if not m and o:
        print(f"  {name:42s} {e}")
print("Mihomo accepts, sidecar rejects:")
for name, m, o, e in rows:
    if m and not o:
        print(f"  {name:42s} sidecar: {golden[name]['error'][:100]}")

if ours:
    print("\nThis converter vs Mihomo:")
    print("Mihomo accepts, this converter rejects:")
    for name, m, _, _ in rows:
        if m and not ours[name]["ok"]:
            print(f"  {name:42s} {ours[name]['error'][:110]}")
    print("Mihomo accepts, this converter accepts but skips rules:")
    for name, m, _, _ in rows:
        if m and ours[name]["ok"] and ours[name].get("skipped"):
            print(f"  {name:42s} skipped={ours[name]['skipped']}")
    print("Mihomo rejects, this converter converts:")
    for name, m, _, e in rows:
        if not m and ours[name]["ok"]:
            print(f"  {name:42s} {e}")
