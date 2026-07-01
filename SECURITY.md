# Security Policy

VibeGate is a security tool, so we treat reports about VibeGate itself with
priority.

## Supported versions

Only the latest released version of VibeGate is supported with security
fixes. Please make sure you're on the latest release before reporting an
issue.

## Reporting a vulnerability

Please do **not** open a public GitHub issue for security vulnerabilities.

Instead, use one of these private channels:

- **Preferred**: [GitHub Security Advisories](https://github.com/theMiddleBlue/vibegate/security/advisories/new)
  ("Report a vulnerability" under the Security tab), if enabled for this repo.
- **Email**: theMiddleBlue@users.noreply.github.com

When reporting, please include:

- A description of the vulnerability and its potential impact
- Steps to reproduce (a minimal snippet of code that triggers the issue is ideal)
- The VibeGate version and host (Claude Code / Codex) you tested against

We aim to acknowledge reports within 72 hours and to provide a fix or
mitigation plan within 14 days for confirmed issues.

## Scope

In scope:

- Bypasses that let a genuinely dangerous pattern (e.g. unsanitized
  `EXEC_INPUT`/`DB_QUERY`) pass through undetected when it should have blocked
- Ways to make VibeGate itself execute attacker-controlled code (e.g. via a
  crafted file being analyzed)
- Privilege or sandbox escapes from the hook process

Generally out of scope:

- False positives / missed detections that are about detection *accuracy*
  rather than a security bypass of the tool itself — please open a normal
  GitHub issue for those
- Vulnerabilities in Semgrep itself (report those to the
  [Semgrep project](https://github.com/semgrep/semgrep))
