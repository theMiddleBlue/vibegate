"""Thin subprocess wrapper around the Semgrep CLI.

Designed to fail safe: any error (Semgrep missing, timeout, malformed output)
returns an empty finding list so the hook degrades to a silent pass rather than
blocking the host tool on an internal problem.
"""

from __future__ import annotations

import glob
import importlib.util
import json
import os
import shutil
import subprocess
import sys
from functools import lru_cache
from pathlib import Path

# Keep below the host hook timeout (Claude Code: 10s) with comfortable margin.
SEMGREP_TIMEOUT_SECONDS = 8

# Common per-user / package-manager bin locations to probe when Semgrep is not
# on PATH — the hook often runs with a minimal PATH that omits ~/.local/bin etc.
_FALLBACK_BIN_GLOBS = (
    "~/.local/bin/semgrep",
    "~/Library/Python/*/bin/semgrep",
    "/opt/homebrew/bin/semgrep",
    "/usr/local/bin/semgrep",
)


@lru_cache(maxsize=1)
def resolve_semgrep_cmd() -> list[str] | None:
    """Locate Semgrep without relying on the caller's PATH.

    Resolution order (first hit wins):
      1. ``VIBEGATE_SEMGREP`` env var (explicit override).
      2. ``semgrep`` on PATH.
      3. Known per-user / Homebrew bin locations.
      4. ``python -m semgrep`` when the package is importable (last resort: it
         still needs its sibling ``semgrep-core`` binary reachable).

    We prefer a real binary path over ``python -m semgrep`` because Semgrep
    shells out to helper binaries (semgrep-core / osemgrep) that live next to it;
    knowing the binary's directory lets ``run_semgrep`` put it on PATH.
    Returns the command prefix as a list, or ``None`` if Semgrep cannot be found.
    """
    override = os.environ.get("VIBEGATE_SEMGREP")
    if override and Path(override).exists():
        return [override]

    on_path = shutil.which("semgrep")
    if on_path:
        return [on_path]

    for pattern in _FALLBACK_BIN_GLOBS:
        for match in sorted(glob.glob(os.path.expanduser(pattern)), reverse=True):
            if os.access(match, os.X_OK):
                return [match]

    if importlib.util.find_spec("semgrep") is not None:
        return [sys.executable, "-m", "semgrep"]

    return None


def _semgrep_env(semgrep_cmd: list[str]) -> dict[str, str]:
    """Subprocess env that guarantees Semgrep can find its helper binaries.

    When we resolved a concrete binary, prepend its directory to PATH so the
    sibling ``semgrep-core`` / ``osemgrep`` it execs are reachable even when the
    hook runs under a minimal PATH.
    """
    env = os.environ.copy()
    binary = semgrep_cmd[0]
    if os.path.isfile(binary):
        bin_dir = os.path.dirname(binary)
        existing = env.get("PATH", "")
        if bin_dir and bin_dir not in existing.split(os.pathsep):
            env["PATH"] = bin_dir + (os.pathsep + existing if existing else "")
    return env


def run_semgrep(file_path: str, rules_dir: Path) -> list[dict]:
    """Run Semgrep against ``file_path`` using the rules in ``rules_dir``.

    Returns the raw ``results`` list from Semgrep's JSON output, or ``[]`` on any
    error. Semgrep infers the target language from the file extension, so no
    ``--lang`` flag is passed (it is only valid with ``-e/--pattern``).
    """
    semgrep_cmd = resolve_semgrep_cmd()
    if semgrep_cmd is None:
        return []

    cmd = [
        *semgrep_cmd,
        "--json",
        "--quiet",
        "--config",
        str(rules_dir),
        file_path,
    ]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=SEMGREP_TIMEOUT_SECONDS,
            env=_semgrep_env(semgrep_cmd),
        )
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return []

    # 0 = no findings, 1 = findings found. Anything else is an error.
    if result.returncode not in (0, 1):
        return []

    try:
        data = json.loads(result.stdout)
    except (json.JSONDecodeError, ValueError):
        return []

    return data.get("results", [])
