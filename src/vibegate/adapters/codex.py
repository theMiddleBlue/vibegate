"""Codex adapter (initial implementation).

NOTE / TODO: Codex's hook event contract is not as stable/documented as Claude
Code's PreToolUse. This adapter implements a best-effort mapping over the shapes
Codex is known to use and is intentionally isolated so it can be hardened later
without touching the core pipeline. Verify against your Codex version before
relying on the blocking path.

Accepted input shapes (first match wins):
  1. Claude-Code-like:  {"tool_name", "tool_input": {"file_path", "content"}}
  2. Flat:              {"path"|"file_path"|"filename", "content"|"text"|"source"}
  3. Patch-style:       {"command": "apply_patch", "path": "...", "content": "..."}

Output:
  - terminal report -> stderr
  - plain-text guidance summary -> stdout
  - exit 2 when blocking, else 0
"""

from __future__ import annotations

import json
import sys

from ..models import AnalysisResult, InputEvent
from .base import HostAdapter

_PATH_KEYS = ("file_path", "path", "filename", "file")
_CONTENT_KEYS = ("content", "new_content", "text", "source", "code")


def _first(d: dict, keys: tuple[str, ...]) -> str:
    for k in keys:
        val = d.get(k)
        if val:
            return val
    return ""


class CodexAdapter(HostAdapter):
    name = "codex"

    def parse_event(self, raw_stdin: str) -> InputEvent | None:
        try:
            event = json.loads(raw_stdin)
        except (json.JSONDecodeError, ValueError):
            return None
        if not isinstance(event, dict):
            return None

        # Shape 1: nested tool_input (Claude-Code-like).
        tool_input = event.get("tool_input")
        if isinstance(tool_input, dict):
            file_path = _first(tool_input, _PATH_KEYS)
            content = _first(tool_input, _CONTENT_KEYS)
        else:
            # Shapes 2 & 3: flat / patch-style.
            file_path = _first(event, _PATH_KEYS)
            content = _first(event, _CONTENT_KEYS)

        if not content:
            return None

        return InputEvent(
            tool_name=event.get("tool_name") or event.get("command", "edit"),
            file_path=file_path or "unknown",
            content=content,
        )

    def emit(self, result: AnalysisResult) -> int:
        if not result.has_findings:
            return 0

        print(result.terminal_output, file=sys.stderr)
        # Codex consumes the plain-text summary on stdout.
        print(result.context_for_host)

        if result.should_block:
            print(result.block_reason, file=sys.stderr)
            return 2
        return 0
