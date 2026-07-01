"""Claude Code PreToolUse adapter.

Input  (stdin JSON) — tool_input shape varies by tool:
    Write:     {"file_path": "...", "content": "..."}
    Edit:      {"file_path": "...", "old_string": "...", "new_string": "..."}
    MultiEdit: {"file_path": "...", "edits": [{"new_string": "..."}, ...]}

For Edit/MultiEdit we reconstruct the full post-edit file from disk (replaying
old_string -> new_string against the current content) so taint rules can see a
source and a sink even when they were introduced by separate edits. Only
findings landing on the lines this edit actually changed are kept — see
``core.analyze``'s use of ``InputEvent.changed_lines``. If reconstruction isn't
possible (new file, old_string no longer matches, unreadable path), we fall
back to scanning just the newly-introduced text, as before.

Output:
    - terminal report -> stderr (visible to the user)
    - {"hookSpecificOutput": {"hookEventName": "PreToolUse",
       "additionalContext": ...}} -> stdout (surfaced to Claude)
    - exit 2 when blocking, else 0
"""

from __future__ import annotations

import difflib
import json
import sys
from pathlib import Path

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


def _edits_for(tool_name: str, tool_input: dict) -> list[dict] | None:
    """Return the ordered old_string/new_string edits for Edit/MultiEdit, or
    None when the payload doesn't carry that shape (Write, or a host-specific
    alias like new_content)."""
    if tool_name == "MultiEdit":
        edits = tool_input.get("edits")
        if isinstance(edits, list) and edits and all(
            isinstance(e, dict) and e.get("old_string") and "new_string" in e
            for e in edits
        ):
            return edits
        return None
    if tool_name == "Edit" and tool_input.get("old_string") and "new_string" in tool_input:
        return [tool_input]
    return None


def _changed_line_ranges(original: str, final: str) -> list[tuple[int, int]]:
    """1-indexed inclusive line ranges in ``final`` that differ from ``original``."""
    orig_lines = original.splitlines()
    final_lines = final.splitlines()
    matcher = difflib.SequenceMatcher(None, orig_lines, final_lines, autojunk=False)
    ranges = []
    for tag, _i1, _i2, j1, j2 in matcher.get_opcodes():
        if tag in ("replace", "insert") and j2 > j1:
            ranges.append((j1 + 1, j2))
    return ranges


def _reconstruct_full_content(
    file_path: str, tool_name: str, tool_input: dict
) -> tuple[str, list[tuple[int, int]]] | None:
    """Rebuild the full post-edit file by replaying old_string -> new_string
    edits against the on-disk content. Returns None when reconstruction isn't
    possible, so the caller can fall back to scanning just the new fragment.
    """
    edits = _edits_for(tool_name, tool_input)
    if not edits:
        return None
    try:
        original = Path(file_path).read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None

    current = original
    for edit in edits:
        old = edit.get("old_string", "")
        new = edit.get("new_string", "")
        if not old or old not in current:
            return None
        if edit.get("replace_all"):
            current = current.replace(old, new)
        else:
            current = current.replace(old, new, 1)

    return current, _changed_line_ranges(original, current)


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
        file_path = tool_input.get("file_path", "unknown")

        changed_lines: list[tuple[int, int]] | None = None
        content: str
        if tool_name in ("Edit", "MultiEdit"):
            reconstructed = _reconstruct_full_content(file_path, tool_name, tool_input)
            if reconstructed:
                content, changed_lines = reconstructed
            else:
                content = _extract_content(tool_input)
        else:
            content = _extract_content(tool_input)

        if not content:
            return None

        return InputEvent(
            tool_name=tool_name,
            file_path=file_path,
            content=content,
            changed_lines=changed_lines,
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
