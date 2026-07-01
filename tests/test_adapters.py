import json

from vibegate.adapters import get_adapter
from vibegate.adapters.claude_code import ClaudeCodeAdapter
from vibegate.adapters.codex import CodexAdapter
from vibegate.core import analyze
from vibegate.models import AnalysisResult, ClassifiedFinding


# --- Claude Code adapter ---

def test_claude_parse_basic():
    raw = json.dumps(
        {
            "tool_name": "Write",
            "tool_input": {"file_path": "/a.py", "content": "x = 1"},
        }
    )
    event = ClaudeCodeAdapter().parse_event(raw)
    assert event is not None
    assert event.file_path == "/a.py"
    assert event.content == "x = 1"


def test_claude_parse_new_content_alias():
    raw = json.dumps(
        {"tool_name": "Edit", "tool_input": {"file_path": "/a.py", "new_content": "y"}}
    )
    event = ClaudeCodeAdapter().parse_event(raw)
    assert event.content == "y"


def test_claude_parse_edit_new_string():
    raw = json.dumps(
        {
            "tool_name": "Edit",
            "tool_input": {
                "file_path": "/a.py",
                "old_string": "pass",
                "new_string": "url = request.args.get('url')",
            },
        }
    )
    event = ClaudeCodeAdapter().parse_event(raw)
    assert event.content == "url = request.args.get('url')"


def test_claude_parse_multiedit_concatenates_new_strings():
    raw = json.dumps(
        {
            "tool_name": "MultiEdit",
            "tool_input": {
                "file_path": "/a.py",
                "edits": [
                    {"old_string": "a", "new_string": "x = 1"},
                    {"old_string": "b", "new_string": "y = 2"},
                ],
            },
        }
    )
    event = ClaudeCodeAdapter().parse_event(raw)
    assert event.content == "x = 1\ny = 2"


def test_claude_edit_reconstructs_full_file_and_blocks_split_taint(tmp_path):
    # Simulates the split-edit bypass: the tainted source already landed on
    # disk (from an earlier edit); this Edit only adds the sink that consumes
    # it. Full-file reconstruction must let the taint rule connect the two.
    f = tmp_path / "app.py"
    f.write_text(
        "from flask import request\nimport sqlite3\n\n"
        "user_id = request.args.get('id')\n"
        "cur = sqlite3.connect('db').cursor()\n"
    )
    raw = json.dumps(
        {
            "tool_name": "Edit",
            "tool_input": {
                "file_path": str(f),
                "old_string": "cur = sqlite3.connect('db').cursor()",
                "new_string": (
                    "cur = sqlite3.connect('db').cursor()\n"
                    "cur.execute(f\"SELECT * FROM users WHERE id={user_id}\")"
                ),
            },
        }
    )
    event = ClaudeCodeAdapter().parse_event(raw)
    assert event is not None
    assert "cur.execute" in event.content
    assert event.changed_lines is not None

    result = analyze(event)
    assert result.should_block
    assert any(f.technical_category == "DB_QUERY" for f in result.classified)


def test_claude_edit_does_not_reblock_pretouched_vulnerability(tmp_path):
    # A pre-existing, untouched EXEC_INPUT line elsewhere in the file must
    # not re-trigger a block on an unrelated edit.
    f = tmp_path / "app.py"
    f.write_text(
        "import os\n"
        "cmd = os.environ.get('CMD')\n"
        "os.system(cmd)\n"
        "\n"
        "def unrelated():\n"
        "    return 1\n"
    )
    raw = json.dumps(
        {
            "tool_name": "Edit",
            "tool_input": {
                "file_path": str(f),
                "old_string": "def unrelated():\n    return 1",
                "new_string": "def unrelated():\n    return 2",
            },
        }
    )
    event = ClaudeCodeAdapter().parse_event(raw)
    assert event is not None
    result = analyze(event)
    assert not result.should_block
    assert not any(f.technical_category == "EXEC_INPUT" for f in result.classified)


def test_claude_edit_falls_back_when_old_string_missing(tmp_path):
    f = tmp_path / "app.py"
    f.write_text("x = 1\n")
    raw = json.dumps(
        {
            "tool_name": "Edit",
            "tool_input": {
                "file_path": str(f),
                "old_string": "this text is not in the file",
                "new_string": "y = 2",
            },
        }
    )
    event = ClaudeCodeAdapter().parse_event(raw)
    assert event is not None
    assert event.content == "y = 2"
    assert event.changed_lines is None


def test_claude_parse_non_write_tool_skipped():
    raw = json.dumps({"tool_name": "Read", "tool_input": {"file_path": "/a.py"}})
    assert ClaudeCodeAdapter().parse_event(raw) is None


def test_claude_parse_malformed_returns_none():
    assert ClaudeCodeAdapter().parse_event("{not json") is None


def test_claude_emit_no_findings_exit_zero(capsys):
    code = ClaudeCodeAdapter().emit(AnalysisResult())
    assert code == 0


def test_claude_emit_warning_exit_zero(capsys):
    result = AnalysisResult(
        classified=[ClassifiedFinding("HTTP_BODY", "EMAIL", 1, "x", "high")],
        terminal_output="report",
        context_for_host="ctx",
        should_block=False,
    )
    code = ClaudeCodeAdapter().emit(result)
    captured = capsys.readouterr()
    assert code == 0
    payload = json.loads(captured.out)
    assert payload["hookSpecificOutput"]["additionalContext"] == "ctx"


def test_claude_emit_block_exit_two(capsys):
    result = AnalysisResult(
        classified=[ClassifiedFinding("DB_QUERY", "PASSWORD", 1, "x", "high")],
        terminal_output="report",
        context_for_host="ctx",
        should_block=True,
        block_reason="blocked",
    )
    code = ClaudeCodeAdapter().emit(result)
    assert code == 2


# --- Codex adapter ---

def test_codex_parse_flat_shape():
    raw = json.dumps({"path": "/a.py", "content": "x = 1"})
    event = CodexAdapter().parse_event(raw)
    assert event is not None
    assert event.file_path == "/a.py"
    assert event.content == "x = 1"


def test_codex_parse_patch_shape():
    raw = json.dumps({"command": "apply_patch", "path": "/a.ts", "source": "let x=1"})
    event = CodexAdapter().parse_event(raw)
    assert event.content == "let x=1"
    assert event.file_path == "/a.ts"


# --- Selection ---

def test_get_adapter_explicit():
    assert get_adapter(name="codex").name == "codex"


def test_get_adapter_default():
    assert get_adapter(name=None, raw_stdin="{}").name == "claude_code"


def test_get_adapter_unknown_falls_back():
    assert get_adapter(name="nope").name == "claude_code"
