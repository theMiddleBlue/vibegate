#!/usr/bin/env python3
"""Entry point for the VibeGate security hook.

Thin orchestrator: read stdin -> pick host adapter -> normalize -> analyze ->
emit. Fail-safe by design: any internal error exits 0 so a hook bug never blocks
the host tool.

Usage:
    python3 hook.py [--host claude_code|codex]

Host selection: --host arg > VIBEGATE_HOST env > payload auto-detect > default.
"""

from __future__ import annotations

import sys
from pathlib import Path

# Support running both as a script (`python3 hook.py`) and as a package module.
if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from vibegate.adapters import get_adapter
    from vibegate.core import analyze
else:
    from .adapters import get_adapter
    from .core import analyze


def _parse_host_arg(argv: list[str]) -> str | None:
    """Extract ``--host VALUE`` or ``--host=VALUE`` from argv, if present."""
    for i, arg in enumerate(argv):
        if arg == "--host" and i + 1 < len(argv):
            return argv[i + 1]
        if arg.startswith("--host="):
            return arg.split("=", 1)[1]
    return None


def main() -> int:
    try:
        raw = sys.stdin.read()
    except Exception:
        return 0

    if not raw.strip():
        return 0

    host = _parse_host_arg(sys.argv[1:])
    adapter = get_adapter(name=host, raw_stdin=raw)

    event = adapter.parse_event(raw)
    if event is None:
        return 0

    result = analyze(event)
    return adapter.emit(result)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except Exception:
        # Never block the host tool on an internal error.
        sys.exit(0)
