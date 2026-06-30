"""Adapter registry + host selection.

Selection order in ``get_adapter``:
  1. explicit ``name`` argument (from ``--host``)
  2. ``VIBEGATE_HOST`` environment variable
  3. auto-detection from the payload
  4. default: claude_code
"""

from __future__ import annotations

import os

from .base import HostAdapter
from .claude_code import ClaudeCodeAdapter
from .codex import CodexAdapter

DEFAULT_HOST = "claude_code"

_REGISTRY: dict[str, type[HostAdapter]] = {
    ClaudeCodeAdapter.name: ClaudeCodeAdapter,
    CodexAdapter.name: CodexAdapter,
}

# Order in which auto-detection is attempted.
_DETECTION_ORDER = (ClaudeCodeAdapter, CodexAdapter)


def available_hosts() -> list[str]:
    return sorted(_REGISTRY)


def get_adapter(name: str | None = None, raw_stdin: str | None = None) -> HostAdapter:
    """Resolve a ``HostAdapter`` from an explicit name, env var, or payload."""
    chosen = name or os.environ.get("VIBEGATE_HOST")

    if not chosen and raw_stdin is not None:
        for adapter_cls in _DETECTION_ORDER:
            try:
                if adapter_cls.detect(raw_stdin):
                    return adapter_cls()
            except Exception:
                continue

    if not chosen:
        chosen = DEFAULT_HOST

    adapter_cls = _REGISTRY.get(chosen)
    if adapter_cls is None:
        # Unknown host: fail safe to the default rather than crashing the hook.
        adapter_cls = _REGISTRY[DEFAULT_HOST]
    return adapter_cls()
