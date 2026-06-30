import os
from pathlib import Path

from user_input_classifier.core import RULES_DIR, analyze, resolve_language
from user_input_classifier.models import InputEvent
from user_input_classifier.semgrep_runner import _semgrep_env, resolve_semgrep_cmd

FIXTURES = Path(__file__).resolve().parent / "fixtures"


def test_resolve_semgrep_env_override(tmp_path, monkeypatch):
    fake = tmp_path / "semgrep"
    fake.write_text("#!/bin/sh\n")
    fake.chmod(0o755)
    monkeypatch.setenv("CLASSIFIER_SEMGREP", str(fake))
    resolve_semgrep_cmd.cache_clear()
    try:
        assert resolve_semgrep_cmd() == [str(fake)]
    finally:
        resolve_semgrep_cmd.cache_clear()


def test_semgrep_env_prepends_binary_dir(tmp_path, monkeypatch):
    fake = tmp_path / "bin" / "semgrep"
    fake.parent.mkdir()
    fake.write_text("#!/bin/sh\n")
    fake.chmod(0o755)
    monkeypatch.setenv("PATH", "/usr/bin")
    env = _semgrep_env([str(fake)])
    assert env["PATH"].split(os.pathsep)[0] == str(fake.parent)


def test_resolve_language():
    assert resolve_language("a.py") == "python"
    assert resolve_language("a.ts") == "typescript"
    assert resolve_language("a.unknown") is None


def test_analyze_unsupported_language_passes():
    event = InputEvent("Write", "notes.txt", "some content")
    result = analyze(event)
    assert not result.has_findings


def test_analyze_empty_content_passes():
    event = InputEvent("Write", "a.py", "")
    result = analyze(event)
    assert not result.has_findings


def test_analyze_http_fixture_detects_email():
    content = (FIXTURES / "test_http.py").read_text()
    event = InputEvent("Write", "test_http.py", content)
    result = analyze(event)
    assert result.has_findings
    cats = {f.technical_category for f in result.classified}
    sems = {f.semantic_type for f in result.classified}
    assert "HTTP_BODY" in cats
    assert "EMAIL" in sems
    assert not result.should_block


def test_analyze_ssrf_sink_detected_regardless_of_varname():
    # The variable is named "target", not "url" — only the sink rule can catch it.
    content = (
        "from flask import request\n"
        "import requests\n"
        "def f():\n"
        "    target = request.args.get('target')\n"
        "    return requests.get(target).text\n"
    )
    result = analyze(InputEvent("Write", "x.py", content))
    assert result.has_findings
    pairs = {(f.technical_category, f.semantic_type) for f in result.classified}
    assert ("URL_FETCH", "URL") in pairs


def test_analyze_constant_url_not_flagged_as_ssrf():
    content = "import requests\nrequests.get('https://api.example.com')\n"
    result = analyze(InputEvent("Write", "x.py", content))
    assert not any(f.technical_category == "URL_FETCH" for f in result.classified)


import pytest


@pytest.mark.parametrize(
    "snippet",
    [
        "import feedparser\nfeedparser.parse(feed.url)\n",
        "import urllib.request\nurllib.request.urlopen(u)\n",
        "import httpx\nhttpx.stream('GET', u)\n",
        "import aiohttp\naiohttp.ClientSession().get(u)\n",
        "import urllib3\nurllib3.request('GET', u)\n",
    ],
)
def test_analyze_python_ssrf_sinks(snippet):
    result = analyze(InputEvent("Write", "x.py", snippet))
    assert any(f.technical_category == "URL_FETCH" for f in result.classified)


@pytest.mark.parametrize(
    "snippet",
    [
        "const r = await fetch(u);\n",
        "const r = await axios.get(u);\n",
        "const r = await got.post(u);\n",
        "http.get(u);\n",
    ],
)
def test_analyze_js_ssrf_sinks(snippet):
    result = analyze(InputEvent("Write", "x.ts", snippet))
    assert any(f.technical_category == "URL_FETCH" for f in result.classified)


def test_analyze_exec_fixture_blocks():
    content = (FIXTURES / "test_exec.py").read_text()
    event = InputEvent("Write", "test_exec.py", content)
    result = analyze(event)
    assert result.has_findings
    cats = {f.technical_category for f in result.classified}
    assert cats & {"EXEC_INPUT", "DB_QUERY"}
    assert result.should_block
    assert result.block_reason
