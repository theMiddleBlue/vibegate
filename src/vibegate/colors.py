"""Shared ANSI color codes, used by both the security report (formatter.py)
and the CLI banner (cli.py) so the two look like one coherent tool."""

from __future__ import annotations

RESET = "\033[0m"
BOLD = "\033[1m"
RED = "\033[91m"
ORANGE = "\033[33m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
CYAN = "\033[96m"
GRAY = "\033[90m"
MINT = "\033[38;5;115m"
