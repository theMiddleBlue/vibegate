# VibeGate

A host-agnostic **pre-write security hook**. It intercepts file writes from an AI
coding tool, uses [Semgrep](https://semgrep.dev) to detect user-input patterns,
and deterministically classifies each into:

- a **technical category** — where the input goes (`HTTP_BODY`, `EXEC_INPUT`, `DB_QUERY`, …)
- a **semantic type** — what the data is (`EMAIL`, `PASSWORD`, `API_KEY`, …)

…then emits static, **no-LLM** security guidance (risks, validation, sanitization).
Warnings are non-blocking; unsanitized `EXEC_INPUT` / `DB_QUERY` block the write.

Supported languages: **Python, JavaScript/TypeScript** (extensible).
Supported hosts: **Claude Code** and **Codex** (pluggable adapters).

## How it works

```
host event (stdin)
  → adapter.parse_event()   # host-specific → normalized InputEvent
  → core.analyze()          # temp file → Semgrep → classify → guidance → format
  → adapter.emit()          # AnalysisResult → host-specific output + exit code
```

The core pipeline never touches host-specific I/O — that lives in `adapters/`.
The hook is **fail-safe**: any internal error exits `0` so a bug never blocks the host.

| Situation | Exit | Effect |
|---|---|---|
| No user input found / unsupported language / internal error | `0` | Silent pass |
| User input detected (warning) | `0` + stdout JSON | Terminal report + context to the host |
| Unsanitized `EXEC_INPUT` or `DB_QUERY` | `2` + stderr | **Blocks** the write + feedback to the host |

## Install

Install once (semgrep comes along as a dependency):

```bash
pipx install git+https://github.com/theMiddleBlue/vibegate
```

Then enable/disable it **per project** — `vibegate on` writes a `PreToolUse`
hook (`Write|Edit|MultiEdit`) into that project's `.claude/settings.local.json`:

```bash
cd your-project
vibegate on        # enable here  (reload Claude Code to activate)
vibegate status    # is it enabled in this project?
vibegate off       # disable here
```

The enabled hook runs `vibegate run --host claude_code` by name (no absolute
paths), so it keeps working wherever the tool is installed.

Host selection at runtime: `--host <name>` → `VIBEGATE_HOST` env → payload
auto-detect → default (`claude_code`).

## Layout

```
src/vibegate/
├── hook.py            # entry point
├── core.py            # host-agnostic pipeline
├── models.py          # InputEvent / ClassifiedFinding / AnalysisResult
├── semgrep_runner.py  # subprocess wrapper (fail-safe)
├── classifier.py      # rule_id → category, varname → semantic type
├── guidance.py        # static risk/remediation tables
├── formatter.py       # ANSI report + host context
├── adapters/          # base, claude_code, codex + registry
└── rules/             # Semgrep YAML (python, js/ts, generic placeholder)
```

## Test

```bash
semgrep --validate --config src/vibegate/rules/   # validate rules
pytest tests/                                                   # unit + integration
```

End-to-end smoke test:

```bash
python3 -c 'import json; print(json.dumps({"tool_name":"Write","tool_input":{"file_path":"/tmp/t.py","new_content":"email = request.json.get(\"email\")"}}))' \
  | python3 src/vibegate/hook.py --host claude_code
```

## Extend

- **New language** — add a `rules/<lang>-user-input.yaml`, register the new rule ids
  in `classifier.RULE_TO_TECHNICAL`, and add the extension to `core.EXT_TO_LANGUAGE`.
- **New semantic type** — add a keyword to `classifier.VARNAME_TO_SEMANTIC` and a card
  to `guidance.SEMANTIC_GUIDANCE`.
- **New technical category** — add a Semgrep rule + `RULE_TO_TECHNICAL` entry + a
  `guidance.TECHNICAL_RISKS` card.
- **New host tool** — add an adapter under `adapters/` and register it in
  `adapters/__init__.py`.

## Notes

- The `codex` adapter is an initial best-effort mapping; verify its event contract
  against your Codex version before relying on the blocking path.
- Semgrep OSS returns `"requires login"` instead of matched source lines; the classifier
  reconstructs snippets from the file content via line numbers to work around this.
