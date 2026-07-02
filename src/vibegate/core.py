"""Host-agnostic analysis pipeline.

``analyze`` takes a normalized ``InputEvent``, runs Semgrep over a temp copy of
the content, classifies the findings, and returns an ``AnalysisResult``. It never
touches host-specific I/O — that is the adapters' job.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

from .classifier import classify_findings
from .formatter import format_output
from .models import AnalysisResult, InputEvent
from .semgrep_runner import run_semgrep

HOOKS_DIR = Path(__file__).resolve().parent
RULES_DIR = HOOKS_DIR / "rules"

# File extension -> Semgrep language. Also the set of supported languages.
EXT_TO_LANGUAGE = {
    ".py": "python",
    ".js": "javascript",
    ".ts": "typescript",
    ".jsx": "javascript",
    ".tsx": "typescript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".go": "go",
    ".java": "java",
    ".php": "php",
    ".rb": "ruby",
    # Not a programming language — covers CI/CD config hardening checks
    # (e.g. unpinned GitHub Actions) via Semgrep's generic/regex mode.
    ".yml": "yaml",
    ".yaml": "yaml",
}


def resolve_language(file_path: str) -> str | None:
    """Map a file path to a supported Semgrep language, or ``None``."""
    return EXT_TO_LANGUAGE.get(Path(file_path).suffix.lower())


def analyze(event: InputEvent, rules_dir: Path = RULES_DIR) -> AnalysisResult:
    """Run the full pipeline for a single ``InputEvent``.

    Returns an empty ``AnalysisResult`` (no findings, no block) when the language
    is unsupported, the content is empty, or Semgrep reports nothing.
    """
    if not event.content:
        return AnalysisResult()

    language = event.language or resolve_language(event.file_path)
    if not language:
        return AnalysisResult()

    ext = Path(event.file_path).suffix.lower() or ".txt"
    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=ext, delete=False, encoding="utf-8"
        ) as tmp:
            tmp.write(event.content)
            tmp_path = tmp.name

        findings = run_semgrep(tmp_path, rules_dir)
        if not findings:
            return AnalysisResult()

        classified = classify_findings(findings, event.content)
        if event.changed_lines is not None:
            # Partial edit: content is the whole reconstructed file (for
            # accurate taint tracing), but only findings inside the lines
            # this specific edit introduced should be surfaced/blocked.
            classified = [
                f
                for f in classified
                if any(start <= f.line <= end for start, end in event.changed_lines)
            ]
        if not classified:
            return AnalysisResult()

        return format_output(classified, event.file_path, language)
    finally:
        if tmp_path:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
