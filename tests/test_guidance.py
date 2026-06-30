import re

import pytest

from user_input_classifier.guidance import SEMANTIC_GUIDANCE, get_guidance

REQUIRED_FIELDS = {
    "validation",
    "validation_regex",
    "sanitization",
    "specific_risks",
    "threat_explanation",
}


@pytest.mark.parametrize("name", sorted(SEMANTIC_GUIDANCE))
def test_entry_has_all_required_fields(name):
    entry = SEMANTIC_GUIDANCE[name]
    missing = REQUIRED_FIELDS - set(entry)
    assert not missing, f"{name} is missing fields: {missing}"
    assert isinstance(entry["validation_regex"], str)
    assert entry["threat_explanation"].strip(), f"{name} has empty threat_explanation"


@pytest.mark.parametrize("name", sorted(SEMANTIC_GUIDANCE))
def test_validation_regex_compiles(name):
    rx = SEMANTIC_GUIDANCE[name]["validation_regex"]
    if rx:  # empty string = regex intentionally not provided
        re.compile(rx)


def test_get_guidance_exposes_new_fields():
    g = get_guidance("HTTP_BODY", "EMAIL")
    assert g["validation_regex"]
    assert g["threat_explanation"]


def test_email_regex_accepts_and_rejects():
    rx = re.compile(SEMANTIC_GUIDANCE["EMAIL"]["validation_regex"])
    assert rx.match("user@example.com")
    assert not rx.match("not-an-email")


def test_ipv4_regex_bounds():
    rx = re.compile(SEMANTIC_GUIDANCE["IP_ADDRESS"]["validation_regex"])
    assert rx.match("192.168.0.1")
    assert not rx.match("999.0.0.1")
