#!/usr/bin/env python3
"""Apply the pending UDP fixes to pinned source copies and print a Go modfile.

Run from any directory. The module cache and repository go.mod are never edited.
Use the printed path with GOFLAGS=-modfile=<path> for make dae / go test.
Remove this temporary integration entry point after publishing both fork patches.
"""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
GO = ROOT / "hack/bin/go"
PATCHES = ROOT / "patches/udp-stability"
DEPENDENCIES = (
    ("outbound", "github.com/daeuniverse/outbound",
     "github.com/Fan-chou/outbound@v0.0.0-sticky-ip.0.20260906020559-8ad471b39caa"),
    ("quic-go", "github.com/olicesx/quic-go",
     "github.com/Fan-chou/quic-go@v0.0.0-20260831031827-fbf90cb0a47d"),
)


def run(*args, **kwargs):
    return subprocess.run(args, cwd=ROOT, check=True, **kwargs)


def main():
    os.environ["GOWORK"] = "off"
    # Download the exact patch bases, independent of any caller's modfile flags.
    os.environ.pop("GOFLAGS", None)
    (ROOT / "build").mkdir(exist_ok=True)
    candidate = Path(tempfile.mkdtemp(prefix="udp-stability-candidate-", dir=ROOT / "build"))
    modfile = candidate / "integration.mod"
    shutil.copyfile(ROOT / "go.mod", modfile)
    shutil.copyfile(ROOT / "go.sum", modfile.with_suffix(".sum"))
    for name, module, base in DEPENDENCIES:
        result = run(str(GO), "mod", "download", "-json", base, capture_output=True, text=True)
        source = Path(json.loads(result.stdout)["Dir"])
        dest = candidate / name
        shutil.copytree(source, dest)
        # Module-cache files are read-only; only these independent copies change.
        for path in dest.rglob("*"):
            path.chmod(path.stat().st_mode | 0o200)
        run("patch", "--batch", "-p1", "-d", str(dest), "-i", str(PATCHES / f"{name}.patch"), stdout=sys.stderr)
        run(str(GO), "mod", "edit", f"-modfile={modfile}", f"-replace={module}={dest}")
    print(modfile)


if __name__ == "__main__":
    main()
