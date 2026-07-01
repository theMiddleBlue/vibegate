<p align="center">
  <img src="assets/logo.png" alt="VibeGate logo" width="420">
</p>

<p align="center">
  <a href="https://github.com/theMiddleBlue/vibegate/actions/workflows/ci.yml"><img src="https://github.com/theMiddleBlue/vibegate/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License: MIT"></a>
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
                    ┌───────────────────────────────┐
                    │   You ask Claude Code to      │
                    │   write or edit a file        │
                    └───────────────┬───────────────┘
                                    │
                                    ▼
                    ┌───────────────────────────────┐
                    │   Claude Code tries to save   │
                    │   the file (Write/Edit tool)  │
                    └───────────────┬───────────────┘
                                    │
                                    ▼
                    ┌───────────────────────────────┐
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
    ┌────────────────────┐ ┌────────────────────┐ ┌──────────────────────┐
    │  No risky input    │ │   Risky input,     │ │  Risky input reaches │
    │  found             │ │   but lower risk   │ │  a critical sink     │
    │                    │ │   (e.g. shown in   │ │  (SQL/command/RCE,   │
    │                    │ │   an HTTP reply)   │ │  template injection) │
    └─────────┬──────────┘ └─────────┬──────────┘ └───────────┬──────────┘
              │                      │                        │
              ▼                      ▼                        ▼
      File is saved,         File is saved,            File is NOT saved.
      nothing shown.         plus a warning in           Claude Code sees
                              the terminal with           the block reason
                              risk + how to fix it.        and is told what
                                                            to fix.
```

In short: safe code passes through untouched, risky-but-survivable code gets
saved with a warning attached, and code that's one step away from things like
SQL injection, command injection, or remote code execution gets stopped
before it ever reaches disk.

If VibeGate itself hits an unexpected error, it always lets the write through
— a bug in the hook should never be the reason your work gets blocked.

| What VibeGate sees | What happens |
|---|---|
| No user input, or a language it doesn't support yet | File saves normally, nothing shown |
| User input found, but the risk is moderate (e.g. open redirect, mass assignment) | File saves, terminal shows a warning + guidance |
| User input flows unsanitized into a critical sink (SQL/NoSQL query, shell command, template engine, deserializer, XML parser, file path, uploaded filename, or raw HTML output) | File is **not saved** — Claude Code is told why |

The full, current list of blocking categories lives in
`formatter.BLOCKING_CATEGORIES` — that's the source of truth if this table
ever drifts.

Today VibeGate understands **Python**, **JavaScript/TypeScript**, **Go**,
**Java**, **PHP**, and **Ruby**, and plugs into **Claude Code** and
**Codex**. More languages and tools can be added without touching the core
logic.

## See it in action

Here is VibeGate working inside Claude Code, while it is building a real app.

In this first example, Claude Code is writing a tool that fetches an RSS
feed. VibeGate notices that the feed address comes from the user, and warns
that this could be used to attack internal servers (this is called SSRF).
Claude Code reads the warning and fixes the code right away, before moving
on to the next file.

<p align="center">
  <img src="assets/vibegate_action_1.png" alt="VibeGate warning Claude Code about an SSRF risk in a feed fetching tool, and Claude Code fixing it" width="720">
</p>

In this second example, Claude Code is building an app that lets people
upload a photo and see its details. VibeGate notices that the file name and
other file details will later be shown on screen, and warns that this could
be used to inject harmful code into the page (this is called XSS). Claude
Code adjusts the code so that information is shown safely.

<p align="center">
  <img src="assets/vibegate_action_2.png" alt="VibeGate warning Claude Code about an XSS risk from uploaded file details, and Claude Code fixing it" width="720">
</p>

In both cases, nothing got blocked for no reason, and no one had to read
through the code line by line to catch the problem. VibeGate caught it the
moment the file was written, and the AI fixed it on the spot.

## Why a gate uses fewer tokens than loading a skill

There are two ways to make an AI assistant write safer code. One way is to
load a big set of instructions about secure coding into the conversation
before it starts, for example a checklist covering SQL injection, XSS,
password handling, file uploads, and more. The other way is what VibeGate
does: check the code automatically, right when a file is written, and only
speak up when something is actually wrong.

The first approach costs tokens on every single message, whether they are
needed or not. A typical secure coding checklist covering several risk
categories can easily add a few thousand tokens. If an AI assistant writes
50 files in one session, and that checklist gets reloaded or kept in context
each time, you could be paying for well over a hundred thousand tokens of
advice that, most of the time, does not apply to the file being written
right now. A login page and a simple color constant file do not need the
same warnings, but a loaded checklist cannot tell them apart in advance.

VibeGate flips this around. It stays silent, and costs nothing extra, for
every file that has no risky pattern in it. Only when it finds something,
like user input flowing into a database query, does it add a short, specific
note about that one issue, usually a small fraction of the size of a full
checklist. So instead of paying a fixed token cost on every file no matter
what, you pay a small cost only on the files that actually need attention,
and that cost is aimed exactly at the problem found, not a general lecture
on security.

This also makes the guidance more reliable. An AI assistant asked to "keep
security in mind" while writing a hundred lines of code can simply miss one
risky line among many. A gate does not get tired or distracted: it checks
every single write, every time, using the same fixed rules.

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

## Suppressing a finding

If VibeGate flags something you've deliberately decided is safe, add a
`vibegate-ignore` comment on the same line — it works with any comment
syntax (`#`, `//`, …), since VibeGate just looks for the text:

```python
query = f"SELECT * FROM users WHERE id = {user_id}"  # vibegate-ignore
```

To suppress only specific categories instead of everything on that line,
list them after a colon (matches either the technical category or the
semantic type, comma-separated, case-insensitive):

```python
query = f"SELECT * FROM users WHERE id = {user_id}"  # vibegate-ignore: DB_QUERY
```

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
└── rules/              # Semgrep rules — one file per language (Python, JS/TS,
                         # Go, Java, PHP, Ruby) plus a generic placeholder
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
- For `Edit`/`MultiEdit`, the `claude_code` adapter reconstructs the full
  post-edit file from disk so a tainted source and a sink introduced by
  *separate* edits are still connected — but only findings on the lines that
  edit actually touched are reported. If a sink already exists and a later
  edit only adds the tainted source that reaches it, that won't be caught
  (the sink's line wasn't part of the new edit). This reconstruction is
  Claude-Code-specific; the `codex` adapter doesn't do it yet.
