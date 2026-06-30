"""Host adapter interface.

A ``HostAdapter`` translates a host tool's raw stdin event into a normalized
``InputEvent`` and renders an ``AnalysisResult`` back into the host's expected
output format + exit code. The core pipeline is host-agnostic; all host-specific
behavior lives behind this interface.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from ..models import AnalysisResult, InputEvent


class HostAdapter(ABC):
    #: Stable identifier used for explicit selection (``--host`` / env var).
    name: str = "base"

    @abstractmethod
    def parse_event(self, raw_stdin: str) -> InputEvent | None:
        """Parse raw stdin into an ``InputEvent``.

        Return ``None`` when there is nothing to scan (wrong tool, no content,
        malformed payload) so the hook can pass silently.
        """

    @abstractmethod
    def emit(self, result: AnalysisResult) -> int:
        """Write host-specific output for ``result`` and return the exit code."""

    @staticmethod
    def detect(raw_stdin: str) -> bool:
        """Best-effort check of whether this adapter fits the given payload.

        Used only for auto-detection when no host is explicitly configured.
        Default: not detectable.
        """
        return False
