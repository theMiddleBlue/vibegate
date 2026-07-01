"""Shared, host-agnostic data contracts passed through the analysis pipeline.

Adapters convert host-specific events into an ``InputEvent`` and render an
``AnalysisResult`` back into host-specific output. The core pipeline only ever
sees these dataclasses, never raw host payloads.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class InputEvent:
    """A normalized request to scan a single file's content.

    Produced by a host adapter from raw stdin. ``language`` is resolved by the
    core pipeline from ``file_path`` when not already known.
    """

    tool_name: str
    file_path: str
    content: str
    language: str | None = None
    changed_lines: list[tuple[int, int]] | None = None
    """1-indexed inclusive (start, end) ranges of lines that this specific
    edit introduced, when known. ``None`` means "no filtering" — every
    finding in ``content`` is in scope (a full ``Write``, or an ``Edit``
    whose full-file reconstruction fell back to scanning just the new
    fragment). When set, only findings landing in one of these ranges should
    be reported, even though ``content`` may be the whole file."""


@dataclass
class ClassifiedFinding:
    """One Semgrep finding after deterministic classification."""

    technical_category: str
    semantic_type: str
    line: int
    snippet: str
    confidence: str  # "high" | "medium" | "low"
    var_name: str | None = None


@dataclass
class AnalysisResult:
    """The outcome of analyzing an ``InputEvent``.

    ``terminal_output`` is the human-facing ANSI report, ``context_for_host`` is
    the plain-text summary surfaced to the host model, and ``should_block`` /
    ``block_reason`` drive the adapter's exit code.
    """

    classified: list[ClassifiedFinding] = field(default_factory=list)
    terminal_output: str = ""
    context_for_host: str = ""
    should_block: bool = False
    block_reason: str = ""

    @property
    def has_findings(self) -> bool:
        return bool(self.classified)
