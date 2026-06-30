<p align="center">
  <img src="assets/logo.png" alt="VibeGate logo" width="420">
</p>

<p align="center">
  A security checkpoint for AI coding tools. It looks at every file an AI
  assistant writes, and stops the dangerous ones before they hit disk.
</p>

## What problem does this solve?

AI coding assistants (Claude Code, Codex, …) write code fast — including code
that handles things like passwords, emails, API keys, or raw user input. It's
easy for an assistant to wire that data straight into a database query, a
shell command, or an HTTP response without thinking about security.

VibeGate sits between the assistant and your filesystem. Every time the
assistant tries to write or edit a file, VibeGate scans the new code first:

- **Finds** user-controlled input in the code (using [Semgrep](https://semgrep.dev))
- **Figures out** what kind of data it is (an email? a password? an API key?)
  and where it's going (a database query? a shell command? an HTTP response?)
- **Warns or blocks**, depending on how risky that combination is

No LLM is involved in the analysis itself — it's fast, deterministic static
analysis, so it never makes things up and never costs you tokens.

## What happens when you turn it on

```
                    ┌─────────────────────────────┐
                    │   You ask Claude Code to     │
                    │   write or edit a file       │
                    └───────────────┬───────────────┘
                                    │
                                    ▼
                    ┌─────────────────────────────┐
                    │   Claude Code tries to save   │
                    │   the file (Write/Edit tool)  │
                    └───────────────┬───────────────┘
                                    │
                                    ▼
                    ┌─────────────────────────────┐
                    │        VibeGate hook          │
                    │   (runs automatically,        │
                    │    before the file is saved)  │
                    └───────────────┬───────────────┘
                                    │
                     scans the new code with Semgrep
                                    │
              ┌─────────────────────┼─────────────────────┐
              │                     │                     │
              ▼                     ▼                     ▼
    ┌──────────────────┐ ┌──────────────────┐ ┌──────────────────────┐
    │  No risky input   │ │   Risky input,    │ │   Risky input going   │
    │  found             │ │   but lower risk  │ │   into a DB query or  │
    │                    │ │   (e.g. shown in  │ │   shell command,       │
    │                    │ │   an HTTP reply)  │ │   not sanitized        │
    └─────────┬──────────┘ └─────────┬──────────┘ └───────────┬───────────┘
              │                      │                        │
              ▼                      ▼                        ▼
      File is saved,         File is saved,            File is NOT saved.
      nothing shown.         plus a warning in           Claude Code sees
                              the terminal with           the block reason
                              risk + how to fix it.        and is told what
                                                            to fix.
```

In short: safe code passes through untouched, risky-but-survivable code gets
saved with a warning attached, and code that's one step away from a SQL
injection or a command injection gets stopped before it ever reaches disk.

If VibeGate itself hits an unexpected error, it always lets the write through
— a bug in the hook should never be the reason your work gets blocked.

| What VibeGate sees | What happens |
|---|---|
| No user input, or a language it doesn't support yet | File saves normally, nothing shown |
| User input found, but the risk is moderate | File saves, terminal shows a warning + guidance |
| User input flows unsanitized into a database query or shell command | File is **not saved** — Claude Code is told why |

Today VibeGate understands **Python** and **JavaScript/TypeScript**, and
plugs into **Claude Code** and **Codex**. More languages and tools can be
added without touching the core logic.

## Getting started

Install it once — this also pulls in Semgrep, which VibeGate relies on:

```bash
pipx install git+https://github.com/theMiddleBlue/vibegate
```

Then turn it on inside whichever project you want protected:

```bash
cd your-project
vibegate on        # turn on here (reload Claude Code afterwards)
vibegate status     # check whether it's on for this project
vibegate off        # turn off here
```

`vibegate on` adds a `PreToolUse` hook for `Write|Edit|MultiEdit` to that
project's `.claude/settings.local.json`. It's scoped per-project, so turning
it on in one repo doesn't affect any other.

Claude Code runs the hook as `vibegate run --host claude_code` — no absolute
paths involved, so it keeps working even if you reinstall or move things
around.

VibeGate figures out which host it's talking to in this order: an explicit
`--host <name>` flag, then the `VIBEGATE_HOST` environment variable, then
auto-detection from the incoming payload, falling back to `claude_code`.

## How the code is organized

```
src/vibegate/
├── hook.py            # entry point
├── core.py            # the host-agnostic pipeline
├── models.py          # InputEvent / ClassifiedFinding / AnalysisResult
├── semgrep_runner.py  # runs Semgrep as a subprocess (fail-safe)
├── classifier.py      # maps Semgrep rule → category, variable name → data type
├── guidance.py         # the static risk/remediation write-ups
├── formatter.py        # turns results into a terminal report + host context
├── adapters/           # base, claude_code, codex + a small registry
└── rules/              # Semgrep rules (Python, JS/TS, and a generic placeholder)
```

The pipeline itself (`core.py`) never talks directly to a specific host — all
host-specific input/output lives in `adapters/`, so adding a new host doesn't
require touching the analysis logic.

## Running the tests

```bash
semgrep --validate --config src/vibegate/rules/   # check the rules are valid
pytest tests/                                      # unit + integration tests
```

To see it work end-to-end without Claude Code:

```bash
python3 -c 'import json; print(json.dumps({"tool_name":"Write","tool_input":{"file_path":"/tmp/t.py","new_content":"email = request.json.get(\"email\")"}}))' \
  | python3 src/vibegate/hook.py --host claude_code
```

## Extending VibeGate

- **Add a language** — add `rules/<lang>-user-input.yaml`, register the new
  rule IDs in `classifier.RULE_TO_TECHNICAL`, and map the file extension in
  `core.EXT_TO_LANGUAGE`.
- **Add a new data type to recognize** — add a keyword to
  `classifier.VARNAME_TO_SEMANTIC` and a write-up in `guidance.SEMANTIC_GUIDANCE`.
- **Add a new sink to detect** (e.g. a new way data can be misused) — add a
  Semgrep rule, an entry in `RULE_TO_TECHNICAL`, and a card in
  `guidance.TECHNICAL_RISKS`.
- **Add a new host tool** — add an adapter under `adapters/` and register it
  in `adapters/__init__.py`.

## Good to know

- The `codex` adapter is an early, best-effort mapping. Double-check its
  event contract against your Codex version before relying on it to block
  anything.
- Semgrep's free tier returns `"requires login"` instead of the actual
  matched line, so the classifier reconstructs the snippet itself from the
  file content using line numbers.
