from user_input_classifier.classifier import classify_findings, extract_varname


def _finding(check_id, line, lines):
    return {
        "check_id": check_id,
        "start": {"line": line},
        "end": {"line": line},
        "extra": {"lines": lines},
    }


def test_classify_http_email():
    findings = [
        _finding(
            "rules.python-http-body-flask", 5, 'email = request.json.get("email")'
        )
    ]
    result = classify_findings(findings, "")
    assert len(result) == 1
    assert result[0].technical_category == "HTTP_BODY"
    assert result[0].semantic_type == "EMAIL"
    assert result[0].confidence == "high"


def test_classify_fallback_free_text():
    findings = [_finding("rules.python-stdin-input", 3, "val = input()")]
    result = classify_findings(findings, "")
    assert result[0].technical_category == "STDIN"
    assert result[0].semantic_type == "FREE_TEXT"
    assert result[0].confidence == "low"


def test_partial_match_medium_confidence():
    findings = [
        _finding(
            "rules.python-http-body-flask",
            5,
            'user_email = request.json.get("user_email")',
        )
    ]
    result = classify_findings(findings, "")
    assert result[0].semantic_type == "EMAIL"
    assert result[0].confidence == "medium"


def test_snippet_reconstructed_from_content_when_login_gated():
    # Semgrep OSS returns "requires login" instead of source lines.
    content = (
        "from flask import request\n"
        'password = request.json.get("password")\n'
    )
    findings = [
        {
            "check_id": "rules.python-http-body-flask",
            "start": {"line": 2},
            "end": {"line": 2},
            "extra": {"lines": "requires login"},
        }
    ]
    result = classify_findings(findings, content)
    assert result[0].semantic_type == "PASSWORD"
    assert result[0].confidence == "high"


def test_dedup_by_category_and_type():
    findings = [
        _finding("rules.python-http-body-flask", 5, 'a = request.json.get("email")'),
        _finding("rules.python-http-body-flask", 6, 'b = request.json.get("email")'),
    ]
    result = classify_findings(findings, "")
    assert len(result) == 1


def test_unknown_rule_dropped():
    findings = [_finding("rules.some-unmapped-rule", 1, "x = 1")]
    assert classify_findings(findings, "") == []


def test_extract_varname_get_call():
    assert extract_varname('request.json.get("email")') == "email"
