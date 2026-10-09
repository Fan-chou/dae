#!/usr/bin/env python3
"""Generate component/mihomo/testdata/convert/golden.json from the archived
dae-rule-sync.

    ORACLE_BIN=/path/to/dae-rule-sync ./gen_convert_goldens.py

Each case is a whole Mihomo configuration (plus optional resolve_dns and
isolate settings). For one run the oracle's nodes, groups, routes, DAT files,
name maps and skip/ignore events are recorded, or its rejection.
"""
import base64
import glob
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

import yaml

here = os.path.dirname(os.path.abspath(__file__))
oracle = os.environ.get("ORACLE_BIN")
if not oracle or not os.access(oracle, os.X_OK):
    sys.exit("set ORACLE_BIN to the archived dae-rule-sync binary")

root = os.path.join(here, "..", "..", "component", "mihomo", "testdata")
spec = yaml.safe_load(open(os.path.join(root, "convert", "cases.yaml")))["cases"]
event_re = re.compile(r'msg="(skip|ignore) Mihomo (?:rule|condition) at index (\d+) line (\d+)')
node_re = re.compile(r"^\s+(\S+): (['\"])(.*)\2$")

out = {}
for name, case in spec.items():
    with tempfile.TemporaryDirectory() as tmp:
        shutil.copytree(os.path.join(root, "providers", "files"), tmp, dirs_exist_ok=True)
        src = os.path.join(tmp, "in.yaml")
        open(src, "w").write(case["config"])
        cmd = [oracle, "-mihomo-routing-config", src, "-generation-dir", os.path.join(tmp, "gen")]
        if case.get("resolve_dns"):
            overlay = os.path.join(tmp, "overlay.json")
            json.dump(case["resolve_dns"], open(overlay, "w"))
            os.chmod(overlay, 0o600)
            cmd += ["-node-resolve-dns", overlay]
        if case.get("isolate"):
            cmd += ["-isolate-transport-groups", case["isolate"]]
        res = subprocess.run(cmd, capture_output=True, text=True, cwd=tmp)
        if res.returncode != 0:
            err = [l for l in res.stderr.strip().splitlines() if l.strip()]
            out[name] = {"ok": False, "error": err[-1] if err else ""}
            continue
        gens = glob.glob(os.path.join(tmp, "gen", "generations", "*"))
        if len(gens) != 1:
            sys.exit(f"{name}: unexpected oracle output layout")
        gen = gens[0]
        nodes = []
        for line in open(os.path.join(gen, "nodes.dae")):
            m = node_re.match(line.rstrip("\n"))
            if m:
                nodes.append([m.group(1), m.group(3)])
        meta = json.load(open(os.path.join(gen, "metadata.json")))["mihomo"]
        dat = {}
        for path in glob.glob(os.path.join(gen, "generated", "**", "*.dat"), recursive=True):
            dat[os.path.relpath(path, gen)] = base64.b64encode(open(path, "rb").read()).decode()
        out[name] = {
            "ok": True,
            "nodes": nodes,
            "groups_dae": open(os.path.join(gen, "groups.dae")).read(),
            "routes_dae": open(os.path.join(gen, "routes.dae")).read(),
            "dat": dat,
            "node_name_map": meta["node_name_map"],
            "group_name_map": meta["group_name_map"],
            "events": [{"kind": k, "index": int(i)} for k, i, _ in event_re.findall(res.stderr)],
        }

with open(os.path.join(root, "convert", "golden.json"), "w") as f:
    json.dump(out, f, ensure_ascii=False, indent=1, sort_keys=True)
    f.write("\n")
ok = sum(1 for v in out.values() if v["ok"])
print(f"{len(out)} cases: {ok} converted, {len(out) - ok} rejected")
