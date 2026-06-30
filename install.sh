#!/usr/bin/env bash
#
# Install the User Input Security Classifier hook into a target project's
# project-local .claude/ directory.
#
# Usage: ./install.sh [TARGET_PROJECT_DIR]   (default: current directory)
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC_PKG="$SCRIPT_DIR/src/user_input_classifier"

TARGET="${1:-$(pwd)}"
TARGET="$(cd "$TARGET" && pwd)"

HOOKS_DEST="$TARGET/.claude/hooks/user_input_classifier"
SETTINGS="$TARGET/.claude/settings.json"

# Importable package name (underscore) so hook.py's imports resolve.
HOOK_CMD='python3 "$CLAUDE_PROJECT_DIR/.claude/hooks/user_input_classifier/hook.py" --host claude_code'

echo "==> Installing into: $TARGET"

# 1. Dependency checks.
command -v python3 >/dev/null 2>&1 || { echo "ERROR: python3 not found." >&2; exit 1; }
if ! command -v semgrep >/dev/null 2>&1; then
  echo "ERROR: semgrep not found. Install it first:" >&2
  echo "    pip install semgrep" >&2
  exit 1
fi

# 2. Copy the package (excluding caches/tests).
echo "==> Copying package to $HOOKS_DEST"
mkdir -p "$HOOKS_DEST"
rsync -a --delete \
  --exclude '__pycache__' \
  --exclude '*.pyc' \
  "$SRC_PKG/" "$HOOKS_DEST/"

# 3. Merge the PreToolUse hook into settings.json (create if absent).
echo "==> Configuring $SETTINGS"
mkdir -p "$(dirname "$SETTINGS")"
HOOK_CMD="$HOOK_CMD" SETTINGS="$SETTINGS" python3 - <<'PY'
import json, os
from pathlib import Path

settings_path = Path(os.environ["SETTINGS"])
hook_cmd = os.environ["HOOK_CMD"]

data = {}
if settings_path.exists():
    try:
        data = json.loads(settings_path.read_text() or "{}")
    except json.JSONDecodeError:
        raise SystemExit(f"ERROR: {settings_path} is not valid JSON; aborting.")

hooks = data.setdefault("hooks", {})
pre = hooks.setdefault("PreToolUse", [])

entry = {
    "matcher": "Write|Edit|MultiEdit",
    "hooks": [
        {
            "type": "command",
            "command": hook_cmd,
            "timeout": 10,
            "statusMessage": "Analyzing user input patterns...",
        }
    ],
}

# Idempotent: replace any existing entry that runs this hook.
def is_ours(e):
    return any(
        "user_input_classifier/hook.py" in (h.get("command", ""))
        for h in e.get("hooks", [])
    )

pre = [e for e in pre if not is_ours(e)]
pre.append(entry)
hooks["PreToolUse"] = pre

settings_path.write_text(json.dumps(data, indent=2) + "\n")
print(f"    merged PreToolUse entry ({len(pre)} total).")
PY

# 4. Make the entry point executable.
chmod +x "$HOOKS_DEST/hook.py"

echo "==> Done. Restart/reload Claude Code in $TARGET to activate the hook."
