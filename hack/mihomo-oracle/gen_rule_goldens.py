#!/usr/bin/env python3
"""Generate component/mihomo/testdata/rules/golden.json from the archived
dae-rule-sync.

    ORACLE_BIN=/path/to/dae-rule-sync ./gen_rule_goldens.py

Each case is a list of Mihomo rules run against fixed proxies and groups
(PROXY, OTHER). Unless the case sets no_match, MATCH,PROXY is appended so the
generation is never empty. The oracle's routes.dae, its skip/ignore log events
(it only reports them on stderr) and any rejection are recorded.
"""
import glob
import json
import os
import re
import subprocess
import sys
import tempfile

import yaml

here = os.path.dirname(os.path.abspath(__file__))
oracle = os.environ.get("ORACLE_BIN")
if not oracle or not os.access(oracle, os.X_OK):
    sys.exit("set ORACLE_BIN to the archived dae-rule-sync binary")

data_dir = os.path.join(here, "..", "..", "component", "mihomo", "testdata", "rules")
spec = yaml.safe_load(open(os.path.join(data_dir, "cases.yaml")))
event_re = re.compile(r'msg="(skip|ignore) Mihomo (?:rule|condition) at index (\d+) line (\d+)')
out = {}
for name, case in spec["cases"].items():
    rules = list(case["rules"])
    if not case.get("no_match"):
        rules.append("MATCH,PROXY")
    doc = {
        "proxies": [{"name": "n1", "type": "ss", "server": "a.example.com", "port": 1,
                     "cipher": "aes-128-gcm", "password": "p"}],
        "proxy-groups": [
            {"name": "PROXY", "type": "select", "proxies": ["n1", "DIRECT"]},
            {"name": "OTHER", "type": "select", "proxies": ["n1"]},
        ],
        "rules": rules,
    }
    with tempfile.TemporaryDirectory() as tmp:
        src = os.path.join(tmp, "in.yaml")
        with open(src, "w") as f:
            yaml.safe_dump(doc, f, allow_unicode=True, default_flow_style=False, width=10**6)
        res = subprocess.run(
            [oracle, "-mihomo-routing-config", src, "-generation-dir", os.path.join(tmp, "gen")],
            capture_output=True, text=True,
        )
        if res.returncode != 0:
            # The fatal error is the last line; earlier lines are skip warnings.
            err = [l for l in res.stderr.strip().splitlines() if l.strip()]
            out[name] = {"ok": False, "error": err[-1] if err else ""}
            continue
        routes = glob.glob(os.path.join(tmp, "gen", "generations", "*", "routes.dae"))
        if len(routes) != 1:
            sys.exit(f"{name}: unexpected oracle output layout")
        events = [{"kind": k, "index": int(i)} for k, i, _ in event_re.findall(res.stderr)]
        out[name] = {"ok": True, "routes_dae": open(routes[0]).read(), "events": events}

with open(os.path.join(data_dir, "golden.json"), "w") as f:
    json.dump(out, f, ensure_ascii=False, indent=1, sort_keys=True)
    f.write("\n")
ok = sum(1 for v in out.values() if v["ok"])
print(f"{len(out)} cases: {ok} converted, {len(out) - ok} rejected")
