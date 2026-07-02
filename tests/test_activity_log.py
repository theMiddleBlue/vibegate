import json

from vibegate import activity_log
from vibegate.models import AnalysisResult, ClassifiedFinding, InputEvent


def _result(*, blocking_category="EXEC_INPUT", warn_category="HTTP_BODY"):
    return AnalysisResult(
        classified=[
            ClassifiedFinding(warn_category, "EMAIL", 2, "snippet-1", "high"),
            ClassifiedFinding(blocking_category, "FREE_TEXT", 5, "snippet-2", "low"),
        ],
        should_block=True,
    )


def test_record_writes_one_entry_per_finding(tmp_path):
    event = InputEvent("Write", "app.py", "content")
    activity_log.record(event, _result(), root=tmp_path)

    path = activity_log.log_path(tmp_path)
    assert path.exists()
    lines = path.read_text().splitlines()
    assert len(lines) == 2

    entries = [json.loads(line) for line in lines]
    assert entries[0]["category"] == "HTTP_BODY"
    assert entries[0]["blocked"] is False
    assert entries[1]["category"] == "EXEC_INPUT"
    assert entries[1]["blocked"] is True
    assert entries[1]["file"] == "app.py"
    assert entries[1]["line"] == 5


def test_record_skips_when_no_findings(tmp_path):
    event = InputEvent("Write", "app.py", "content")
    activity_log.record(event, AnalysisResult(), root=tmp_path)
    assert not activity_log.log_path(tmp_path).exists()


def test_record_truncates_long_snippet(tmp_path):
    long_snippet = "x" * 1000
    result = AnalysisResult(
        classified=[ClassifiedFinding("EXEC_INPUT", "FREE_TEXT", 1, long_snippet, "low")],
        should_block=True,
    )
    activity_log.record(InputEvent("Write", "a.py", "c"), result, root=tmp_path)
    entries = activity_log.read_entries(root=tmp_path)
    assert len(entries[0]["snippet"]) == activity_log.SNIPPET_MAX_LEN


def test_record_caps_total_entries(tmp_path):
    event = InputEvent("Write", "app.py", "content")
    for i in range(activity_log.MAX_ENTRIES + 10):
        result = AnalysisResult(
            classified=[ClassifiedFinding("HTTP_BODY", "EMAIL", i, "s", "high")],
        )
        activity_log.record(event, result, root=tmp_path)

    entries = activity_log.read_entries(root=tmp_path)
    assert len(entries) == activity_log.MAX_ENTRIES
    # Oldest entries were dropped; the most recent ones survive.
    assert entries[-1]["line"] == activity_log.MAX_ENTRIES + 9


def test_read_entries_respects_limit(tmp_path):
    event = InputEvent("Write", "app.py", "content")
    for i in range(5):
        result = AnalysisResult(
            classified=[ClassifiedFinding("HTTP_BODY", "EMAIL", i, "s", "high")],
        )
        activity_log.record(event, result, root=tmp_path)

    assert len(activity_log.read_entries(root=tmp_path)) == 5
    limited = activity_log.read_entries(limit=2, root=tmp_path)
    assert len(limited) == 2
    assert limited[-1]["line"] == 4


def test_read_entries_empty_when_no_log(tmp_path):
    assert activity_log.read_entries(root=tmp_path) == []
