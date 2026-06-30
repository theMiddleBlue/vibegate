"""VibeGate command-line interface.

One entry point, four subcommands:

    vibegate run [--host HOST]   # the hook itself: reads a tool event on stdin
    vibegate on                  # enable the hook in ./.claude/settings.local.json
    vibegate off                 # disable it (idempotent)
    vibegate status              # report whether it is enabled in this project

``on``/``off`` operate on the CURRENT project's personal settings
(``.claude/settings.local.json``), so activation is per-project and reversible
with a single command. The enabled hook invokes ``vibegate run`` by name — no
absolute paths — so it keeps working wherever the tool is installed (e.g. pipx).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from .hook import main as hook_main

MATCHER = "Write|Edit|MultiEdit"
HOOK_COMMAND = "vibegate run --host claude_code"
STATUS_MESSAGE = "VibeGate: analyzing user-input patterns..."
SETTINGS_REL = Path(".claude") / "settings.local.json"


def _settings_path() -> Path:
    return Path.cwd() / SETTINGS_REL


def _load(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text() or "{}")
    except json.JSONDecodeError:
        raise SystemExit(f"ERROR: {path} is not valid JSON; aborting.")


def _save(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + "\n")


def _is_ours(entry: dict) -> bool:
    return any("vibegate" in h.get("command", "") for h in entry.get("hooks", []))


def _our_entry() -> dict:
    return {
        "matcher": MATCHER,
        "hooks": [
            {
                "type": "command",
                "command": HOOK_COMMAND,
                "timeout": 10,
                "statusMessage": STATUS_MESSAGE,
            }
        ],
    }


def enable() -> int:
    path = _settings_path()
    data = _load(path)
    hooks = data.setdefault("hooks", {})
    # Idempotent: drop any existing VibeGate entry, then add a fresh one.
    pre = [e for e in hooks.get("PreToolUse", []) if not _is_ours(e)]
    pre.append(_our_entry())
    hooks["PreToolUse"] = pre
    _save(path, data)
    print(f"VibeGate enabled in {path}")
    print("Reload/restart Claude Code in this project to activate it.")
    return 0


def disable() -> int:
    path = _settings_path()
    if not path.exists():
        print(f"VibeGate is not enabled here (no {path}).")
        return 0
    data = _load(path)
    hooks = data.get("hooks", {})
    pre = [e for e in hooks.get("PreToolUse", []) if not _is_ours(e)]
    if pre:
        hooks["PreToolUse"] = pre
    else:
        hooks.pop("PreToolUse", None)
    if not hooks:
        data.pop("hooks", None)
    _save(path, data)
    print(f"VibeGate disabled in {path}")
    return 0


def status() -> int:
    path = _settings_path()
    data = _load(path)
    enabled = any(
        _is_ours(e) for e in data.get("hooks", {}).get("PreToolUse", [])
    )
    print(f"VibeGate is {'ENABLED' if enabled else 'NOT enabled'} in {path}")
    return 0


_USAGE = (
    "usage: vibegate {run|on|off|status}\n"
    "  run [--host HOST]  hook entry point (reads a tool event on stdin)\n"
    "  on                 enable in ./.claude/settings.local.json\n"
    "  off                disable in this project\n"
    "  status             show whether enabled here\n"
)


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    cmd = args[0] if args else ""

    if cmd == "run":
        # Fail-safe: a hook bug must never block the host tool (exit 0).
        try:
            return hook_main()
        except SystemExit:
            raise
        except Exception:
            return 0
    if cmd in ("on", "enable"):
        return enable()
    if cmd in ("off", "disable"):
        return disable()
    if cmd == "status":
        return status()

    sys.stderr.write(_USAGE)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
