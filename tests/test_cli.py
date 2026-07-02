import json

from vibegate import activity_log, cli
from vibegate.models import AnalysisResult, ClassifiedFinding, InputEvent


def _read(tmp_path):
    p = tmp_path / ".claude" / "settings.local.json"
    return json.loads(p.read_text())


def test_enable_creates_idempotent_entry(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    assert cli.main(["on"]) == 0
    assert cli.main(["on"]) == 0  # idempotent
    pre = _read(tmp_path)["hooks"]["PreToolUse"]
    assert len(pre) == 1
    cmd = pre[0]["hooks"][0]["command"]
    assert "vibegate run" in cmd
    assert pre[0]["matcher"] == "Write|Edit|MultiEdit"


def test_disable_removes_entry_and_cleans_up(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    cli.main(["on"])
    assert cli.main(["off"]) == 0
    assert _read(tmp_path) == {}


def test_enable_preserves_foreign_hooks(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    settings = tmp_path / ".claude" / "settings.local.json"
    settings.parent.mkdir(parents=True)
    settings.write_text(
        json.dumps(
            {
                "hooks": {
                    "PreToolUse": [
                        {"matcher": "Bash", "hooks": [{"command": "other-tool"}]}
                    ]
                }
            }
        )
    )
    cli.main(["on"])
    pre = _read(tmp_path)["hooks"]["PreToolUse"]
    commands = [h["command"] for e in pre for h in e["hooks"]]
    assert "other-tool" in commands
    assert any("vibegate run" in c for c in commands)
    # Disable must leave the foreign hook untouched.
    cli.main(["off"])
    pre = _read(tmp_path)["hooks"]["PreToolUse"]
    commands = [h["command"] for e in pre for h in e["hooks"]]
    assert commands == ["other-tool"]


def test_status_reports_state(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    assert cli.main(["status"]) == 0
    assert "NOT enabled" in capsys.readouterr().out
    cli.main(["on"])
    assert cli.main(["status"]) == 0
    assert "ENABLED" in capsys.readouterr().out


def test_unknown_command_returns_usage(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    assert cli.main(["bogus"]) == 2
    assert "usage: vibegate" in capsys.readouterr().err


def test_on_off_status_show_the_banner(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    for args in (["on"], ["off"], ["status"]):
        cli.main(args)
        out = capsys.readouterr().out
        for row in cli._BANNER_ROWS:
            assert row in out


def test_status_with_no_activity(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    cli.main(["status"])
    assert "No activity recorded yet" in capsys.readouterr().out


def test_status_lists_recent_activity_most_recent_first(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    event = InputEvent("Write", "app.py", "content")
    activity_log.record(
        event,
        AnalysisResult(
            classified=[ClassifiedFinding("HTTP_BODY", "EMAIL", 2, "s", "high")]
        ),
    )
    activity_log.record(
        event,
        AnalysisResult(
            classified=[ClassifiedFinding("EXEC_INPUT", "FREE_TEXT", 5, "s", "low")],
            should_block=True,
        ),
    )

    cli.main(["status"])
    out = capsys.readouterr().out
    assert "EXEC_INPUT" in out
    assert "HTTP_BODY" in out
    assert "BLOCKED" in out
    assert "WARNED" in out
    # Most recent (EXEC_INPUT) must be listed before the older HTTP_BODY entry.
    assert out.index("EXEC_INPUT") < out.index("HTTP_BODY")


def test_status_limit_argument(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    event = InputEvent("Write", "app.py", "content")
    for i in range(5):
        activity_log.record(
            event,
            AnalysisResult(
                classified=[ClassifiedFinding("HTTP_BODY", "EMAIL", i, "s", "high")]
            ),
        )
    cli.main(["status", "2"])
    out = capsys.readouterr().out
    assert "last 2 of 5 recorded" in out


def test_status_rejects_non_numeric_limit(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    assert cli.main(["status", "not-a-number"]) == 2
    assert "ERROR" in capsys.readouterr().err
