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
