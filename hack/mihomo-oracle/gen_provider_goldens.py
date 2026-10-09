#!/usr/bin/env python3
"""Generate component/mihomo/testdata/providers/golden.json from the archived
dae-rule-sync.

    ORACLE_BIN=/path/to/dae-rule-sync ./gen_provider_goldens.py

Each case declares rule-providers backed by files in testdata/providers/files
and a list of rules. Recorded per case: the oracle's routes.dae, its skip and
ignore events (stderr only), the DAT files it generated for large providers
(base64, keyed by path relative to the generation), or its rejection.
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

data = os.path.join(here, "..", "..", "component", "mihomo", "testdata", "providers")
spec = yaml.safe_load(open(os.path.join(data, "cases.yaml")))["cases"]
event_re = re.compile(r'msg="(skip|ignore) Mihomo (?:rule|condition) at index (\d+) line (\d+)')


def provider_doc(decl):
    d = {}
    if "type" in decl:
        d["type"] = decl["type"]
    elif "url" not in decl:
        d["type"] = "file"
    for key in ("url", "behavior", "format", "interval"):
        if key in decl:
            d[key] = decl[key]
    if "path" in decl:
        d["path"] = decl["path"]
    elif "file" in decl:
        d["path"] = decl["file"]
    return d


out = {}
for name, case in spec.items():
    rules = list(case["rules"]) + ([] if case.get("no_match") else ["MATCH,PROXY"])
    doc = {
        "proxies": [{"name": "n1", "type": "ss", "server": "a.example.com", "port": 1,
                     "cipher": "aes-128-gcm", "password": "p"}],
        "proxy-groups": [
            {"name": "PROXY", "type": "select", "proxies": ["n1", "DIRECT"]},
            {"name": "OTHER", "type": "select", "proxies": ["n1"]},
        ],
        "rules": rules,
    }
    if case.get("providers"):
        doc["rule-providers"] = {p: provider_doc(d) for p, d in case["providers"].items()}
    if case.get("sub_rules"):
        doc["sub-rules"] = case["sub_rules"]
    with tempfile.TemporaryDirectory() as tmp:
        shutil.copytree(os.path.join(data, "files"), tmp, dirs_exist_ok=True)
        src = os.path.join(tmp, "in.yaml")
        with open(src, "w") as f:
            yaml.safe_dump(doc, f, allow_unicode=True, default_flow_style=False, width=10**6)
        gen = os.path.join(tmp, "gen")
        res = subprocess.run([oracle, "-mihomo-routing-config", src, "-generation-dir", gen],
                             capture_output=True, text=True, cwd=tmp)
        if res.returncode != 0:
            err = [l for l in res.stderr.strip().splitlines() if l.strip()]
            out[name] = {"ok": False, "error": err[-1] if err else ""}
            continue
        generation = glob.glob(os.path.join(gen, "generations", "*"))
        if len(generation) != 1:
            sys.exit(f"{name}: unexpected oracle output layout")
        generation = generation[0]
        dat = {}
        for path in glob.glob(os.path.join(generation, "generated", "**", "*.dat"), recursive=True):
            dat[os.path.relpath(path, generation)] = base64.b64encode(open(path, "rb").read()).decode()
        events = [{"kind": k, "index": int(i)} for k, i, _ in event_re.findall(res.stderr)]
        out[name] = {"ok": True,
                     "routes_dae": open(os.path.join(generation, "routes.dae")).read(),
                     "events": events, "dat": dat}

with open(os.path.join(data, "golden.json"), "w") as f:
    json.dump(out, f, ensure_ascii=False, indent=1, sort_keys=True)
    f.write("\n")
ok = sum(1 for v in out.values() if v["ok"])
dats = sum(1 for v in out.values() if v.get("dat"))
print(f"{len(out)} cases: {ok} converted ({dats} with DAT), {len(out) - ok} rejected")
