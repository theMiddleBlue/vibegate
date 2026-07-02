"""Local record of every VibeGate warning/block, so `vibegate status` can show
what happened and why over time — not just whether the hook is enabled.

Stored as JSON Lines at ``.vibegate/activity.jsonl`` under the current working
directory (the project root, since that's where Claude Code runs the hook
from). Deliberately not under ``.claude/``: this is VibeGate's own state, not
tied to any specific host's config directory.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from .formatter import BLOCKING_CATEGORIES
from .models import AnalysisResult, InputEvent

LOG_DIR = ".vibegate"
LOG_FILE = "activity.jsonl"
MAX_ENTRIES = 500
SNIPPET_MAX_LEN = 200


def log_path(root: Path | None = None) -> Path:
    return (root or Path.cwd()) / LOG_DIR / LOG_FILE


def record(
    event: InputEvent, result: AnalysisResult, root: Path | None = None
) -> None:
    """Append one entry per finding. Best-effort: a logging failure must never
    break the analysis pipeline, so any error here is swallowed."""
    if not result.has_findings:
        return
    try:
        path = log_path(root)
        path.parent.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now(timezone.utc).isoformat(timespec="seconds")

        new_lines = []
        for finding in result.classified:
            entry = {
                "timestamp": timestamp,
                "file": event.file_path,
                "category": finding.technical_category,
                "semantic_type": finding.semantic_type,
                "line": finding.line,
                "snippet": finding.snippet[:SNIPPET_MAX_LEN],
                "blocked": finding.technical_category in BLOCKING_CATEGORIES,
            }
            new_lines.append(json.dumps(entry))

        existing = path.read_text().splitlines() if path.exists() else []
        combined = (existing + new_lines)[-MAX_ENTRIES:]
        path.write_text("\n".join(combined) + "\n")
    except OSError:
        pass


def read_entries(limit: int | None = None, root: Path | None = None) -> list[dict]:
    """Return stored entries, oldest first. Malformed lines are skipped."""
    path = log_path(root)
    if not path.exists():
        return []
    entries = []
    for line in path.read_text().splitlines():
        try:
            entries.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return entries[-limit:] if limit else entries
