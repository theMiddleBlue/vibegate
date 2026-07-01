# Contributing to VibeGate

Thanks for considering a contribution. VibeGate is a small, focused tool —
most contributions fall into one of these buckets:

- A new Semgrep rule for a language/framework combo we don't cover yet
- A new vulnerability category (a new kind of dangerous sink)
- A new semantic type (a new kind of sensitive data to recognize)
- A new host adapter (a coding tool other than Claude Code / Codex)
- Bug fixes, test coverage, or documentation improvements

See the [README's "Extending VibeGate" section](README.md#extending-vibegate)
for exactly which files each of these touches.

## Getting set up

```bash
git clone https://github.com/theMiddleBlue/vibegate
cd vibegate
pip install -e ".[dev]"
```

## Before opening a pull request

```bash
semgrep --validate --config src/vibegate/rules/   # your rules must be valid YAML/Semgrep
pytest tests/                                      # the full suite must pass
```

If you add a new rule, please also add:

- A test in `tests/test_semgrep_runner.py` that proves the rule fires on a
  realistic vulnerable snippet (see the existing tests for the pattern —
  build an `InputEvent`, call `analyze()`, assert on `result.classified` and
  `result.should_block`)
- If you introduce a new semantic type, an entry in
  `guidance.SEMANTIC_GUIDANCE` with all required fields (`test_guidance.py`
  will fail otherwise)

## Rule design principles

These aren't hard rules, but they explain the choices already made in
`src/vibegate/rules/`, so new rules stay consistent:

- **Taint mode** (`mode: taint`) for sink detection when we can distinguish a
  "safe" call shape (e.g. a parameterized SQL query) from a "dangerous" one
  (e.g. string interpolation into the query). Only the dangerous shape should
  match.
- **Presence mode** (a plain pattern excluding string literals via
  `metavariable-regex`) for cases where the hook can't reliably trace taint
  across a whole request lifecycle — SSRF, SSTI, open redirect. See the
  comments in `python-user-input.yaml` for the reasoning.
- Prefer a few well-known, common sinks (the standard library or the most
  popular framework) over trying to cover every library — a rule that's 90%
  accurate for the common case beats one that tries to be exhaustive and
  becomes unmaintainable.
- Add a short comment above any rule that isn't self-explanatory, especially
  documenting *why* a certain shape is excluded (a known false-positive
  case) or a known gap (something the rule deliberately doesn't catch).

## Reporting bugs vs. security issues

- **Bugs, false positives, missing detections, feature requests** → open a
  normal [GitHub issue](https://github.com/theMiddleBlue/vibegate/issues).
- **Security vulnerabilities in VibeGate itself** → see
  [SECURITY.md](SECURITY.md), please don't open a public issue.

## Pull requests

- Keep PRs focused — one rule/category/fix per PR is easier to review than a
  bundle of unrelated changes.
- Explain the *why* in the PR description (what's the real-world bug this
  catches, or what was broken).
- CI runs `semgrep --validate` and `pytest` automatically; please make sure
  both pass locally first.
