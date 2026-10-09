#!/usr/bin/env python3
"""Generate component/mihomo/testdata/groups/golden.json from the archived
dae-rule-sync.

    ORACLE_BIN=/path/to/dae-rule-sync ./gen_group_goldens.py

Each case in testdata/groups/cases.yaml is run with the shared proxies. The
oracle's groups.dae text (or its rejection) is recorded; tests parse that text
with dae's own config parser and compare it with the in-memory conversion.
"""
import glob
import json
import os
import subprocess
import sys
import tempfile

import yaml

here = os.path.dirname(os.path.abspath(__file__))
oracle = os.environ.get("ORACLE_BIN")
if not oracle or not os.access(oracle, os.X_OK):
    sys.exit("set ORACLE_BIN to the archived dae-rule-sync binary")

data_dir = os.path.join(here, "..", "..", "component", "mihomo", "testdata", "groups")
spec = yaml.safe_load(open(os.path.join(data_dir, "cases.yaml")))
out = {}
for name, case in spec["cases"].items():
    doc = {
        "proxies": case.get("proxies", spec["proxies"]),
        "proxy-groups": case["groups"],
        "rules": ["MATCH,DIRECT"],
    }
    with tempfile.TemporaryDirectory() as tmp:
        src = os.path.join(tmp, "in.yaml")
        with open(src, "w") as f:
            yaml.safe_dump(doc, f, allow_unicode=True, default_flow_style=False)
        gen = os.path.join(tmp, "gen")
        cmd = [oracle, "-mihomo-routing-config", src, "-generation-dir", gen]
        if case.get("isolate"):
            cmd += ["-isolate-transport-groups", case["isolate"]]
        res = subprocess.run(cmd, capture_output=True, text=True)
        if res.returncode != 0:
            err = res.stderr.strip().splitlines()
            out[name] = {"ok": False, "error": err[0] if err else ""}
            continue
        groups = glob.glob(os.path.join(gen, "generations", "*", "groups.dae"))
        meta = glob.glob(os.path.join(gen, "generations", "*", "metadata.json"))
        if len(groups) != 1 or len(meta) != 1:
            sys.exit(f"{name}: unexpected oracle output layout")
        m = json.load(open(meta[0]))["mihomo"]
        out[name] = {
            "ok": True,
            "groups_dae": open(groups[0]).read(),
            "group_name_map": m["group_name_map"],
        }

with open(os.path.join(data_dir, "golden.json"), "w") as f:
    json.dump(out, f, ensure_ascii=False, indent=1, sort_keys=True)
    f.write("\n")
ok = sum(1 for v in out.values() if v["ok"])
print(f"{len(out)} cases: {ok} converted, {len(out) - ok} rejected")
