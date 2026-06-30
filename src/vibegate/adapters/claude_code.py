"""Claude Code PreToolUse adapter.

Input  (stdin JSON) — tool_input shape varies by tool:
    Write:     {"file_path": "...", "content": "..."}
    Edit:      {"file_path": "...", "old_string": "...", "new_string": "..."}
    MultiEdit: {"file_path": "...", "edits": [{"new_string": "..."}, ...]}
We analyze only the text being introduced (content / new_string), never the
old_string being replaced.

Output:
    - terminal report -> stderr (visible to the user)
    - {"hookSpecificOutput": {"hookEventName": "PreToolUse",
       "additionalContext": ...}} -> stdout (surfaced to Claude)
    - exit 2 when blocking, else 0
"""

from __future__ import annotations

import json
import sys

from ..models import AnalysisResult, InputEvent
from .base import HostAdapter

WRITE_TOOLS = {"Write", "Edit", "MultiEdit"}


def _extract_content(tool_input: dict) -> str:
    """Pull the newly-introduced text out of any Write/Edit/MultiEdit payload.

    Write carries ``content`` (``new_content`` on some hosts), Edit carries
    ``new_string``, and MultiEdit carries a list of ``edits`` each with its own
    ``new_string``. We only look at text being added, not the ``old_string``
    being removed.
    """
    # MultiEdit: concatenate the new side of every edit.
    edits = tool_input.get("edits")
    if isinstance(edits, list):
        parts = [
            e.get("new_string", "")
            for e in edits
            if isinstance(e, dict) and e.get("new_string")
        ]
        if parts:
            return "\n".join(parts)

    # Write (content / new_content) or Edit (new_string).
    return (
        tool_input.get("new_content")
        or tool_input.get("content")
        or tool_input.get("new_string", "")
    )


class ClaudeCodeAdapter(HostAdapter):
    name = "claude_code"

    def parse_event(self, raw_stdin: str) -> InputEvent | None:
        try:
            event = json.loads(raw_stdin)
        except (json.JSONDecodeError, ValueError):
            return None

        tool_name = event.get("tool_name", "")
        if tool_name and tool_name not in WRITE_TOOLS:
            return None

        tool_input = event.get("tool_input", {}) or {}
        content = _extract_content(tool_input)
        file_path = tool_input.get("file_path", "unknown")

        if not content:
            return None

        return InputEvent(
            tool_name=tool_name, file_path=file_path, content=content
        )

    def emit(self, result: AnalysisResult) -> int:
        if not result.has_findings:
            return 0

        # Human-facing report on stderr.
        print(result.terminal_output, file=sys.stderr)

        # Structured context for Claude on stdout.
        output = {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "additionalContext": result.context_for_host,
            }
        }
        print(json.dumps(output))

        if result.should_block:
            print(result.block_reason, file=sys.stderr)
            return 2
        return 0

    @staticmethod
    def detect(raw_stdin: str) -> bool:
        try:
            event = json.loads(raw_stdin)
        except (json.JSONDecodeError, ValueError):
            return False
        return "tool_name" in event and "tool_input" in event
