#!/usr/bin/env python3
"""Rewrite agent Shell calls so go/make inherit durable GOCACHE."""
from __future__ import annotations

import json
import os
import re
import sys

GO_CMD = re.compile(r"(^|[;&|(\s])go(\s|$)")
MAKE_CMD = re.compile(r"(^|[;&|(\s])make(\s|$)")


def allow(payload: dict | None = None) -> None:
    sys.stdout.write(json.dumps(payload or {"permission": "allow"}))
    sys.exit(0)


def main() -> None:
    raw = sys.stdin.read()
    try:
        data = json.loads(raw) if raw.strip() else {}
    except json.JSONDecodeError:
        allow()
        return

    tool_input = data.get("tool_input") or data.get("arguments") or {}
    if not isinstance(tool_input, dict):
        tool_input = {}
    command = tool_input.get("command") or data.get("command") or ""
    if not command:
        allow()
        return
    if "hack/env.sh" in command or "hack/bin" in command:
        allow()
        return
    if not GO_CMD.search(command) and not MAKE_CMD.search(command):
        allow()
        return

    here = os.path.dirname(os.path.abspath(__file__))
    root = os.path.dirname(os.path.dirname(here))
    envsh = os.path.join(root, "hack", "env.sh")
    bindir = os.path.join(root, "hack", "bin")
    if not os.path.isfile(envsh):
        allow()
        return

    prefix = f'export PATH="{bindir}:$PATH"; export KDAE_ROOT="{root}"; . "{envsh}"; '
    updated = dict(tool_input)
    updated["command"] = prefix + command
    allow({"permission": "allow", "updated_input": updated})


if __name__ == "__main__":
    main()
