#!/usr/bin/env python3
"""Generate component/mihomo/testdata/nodes/golden.json from the archived
dae-rule-sync (the behaviour oracle).

    ORACLE_BIN=/path/to/dae-rule-sync ./gen_node_goldens.py

Each case in testdata/nodes/cases.yaml is a single Mihomo proxy. The oracle's result is
recorded as either the converted dae node (safe name, protocol, link) or a
rejection. Error texts are kept for humans only; tests compare accept/reject
and the produced name/link.
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

cases = yaml.safe_load(open(os.path.join(here, "..", "..", "component", "mihomo", "testdata", "nodes", "cases.yaml")))
out = {}
for case, proxy in cases.items():
    doc = {
        "proxies": [proxy],
        "proxy-groups": [{"name": "G", "type": "select", "proxies": [proxy["name"]]}],
        "rules": ["MATCH,DIRECT"],
    }
    with tempfile.TemporaryDirectory() as tmp:
        src = os.path.join(tmp, "in.yaml")
        with open(src, "w") as f:
            yaml.safe_dump(doc, f, allow_unicode=True, default_flow_style=False)
        gen = os.path.join(tmp, "gen")
        res = subprocess.run(
            [oracle, "-mihomo-routing-config", src, "-generation-dir", gen],
            capture_output=True, text=True,
        )
        if res.returncode != 0:
            out[case] = {"ok": False, "error": res.stderr.strip().splitlines()[0] if res.stderr.strip() else ""}
            continue
        nodes = glob.glob(os.path.join(gen, "generations", "*", "nodes.dae"))
        meta = glob.glob(os.path.join(gen, "generations", "*", "metadata.json"))
        if len(nodes) != 1 or len(meta) != 1:
            sys.exit(f"{case}: unexpected oracle output layout")
        lines = [l for l in open(nodes[0]).read().splitlines() if l.startswith("    ")]
        if len(lines) != 1:
            sys.exit(f"{case}: expected one node, got {len(lines)}")
        safe, _, quoted = lines[0].strip().partition(": ")
        link = quoted[1:-1]
        m = json.load(open(meta[0]))["mihomo"]
        assert m["node_name_map"][proxy["name"]] == safe, case
        out[case] = {"ok": True, "name": proxy["name"], "safe": safe,
                     "type": m["node_types"][safe], "link": link}

dest = os.path.join(here, "..", "..", "component", "mihomo", "testdata", "nodes", "golden.json")
os.makedirs(os.path.dirname(dest), exist_ok=True)
with open(dest, "w") as f:
    json.dump(out, f, ensure_ascii=False, indent=1, sort_keys=True)
    f.write("\n")
ok = sum(1 for v in out.values() if v["ok"])
print(f"{len(out)} cases: {ok} converted, {len(out)-ok} rejected -> {os.path.normpath(dest)}")
