import json

from vibegate import cli


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
