import json

import pytest

from src.rule_loader import load_rules


def test_load_valid_rules():
    rules = load_rules()

    assert isinstance(rules, list)
    assert len(rules) >= 7

    rule_ids = [rule["id"] for rule in rules]

    assert len(rule_ids) == len(set(rule_ids))

    expected_ids = {
        "LOL-001",
        "LOL-002",
        "LOL-003",
        "LOL-004",
        "LOL-005",
        "LOL-006"
    }

    assert expected_ids.issubset(set(rule_ids))


def test_invalid_json(tmp_path):
    file_path = tmp_path / "invalid.json"
    file_path.write_text("{invalid json", encoding="utf-8")

    with pytest.raises(ValueError, match="Invalid JSON"):
        load_rules(file_path)


def test_duplicate_rule_id(tmp_path):
    rules = load_rules()
    rules[1]["id"] = rules[0]["id"]

    file_path = tmp_path / "duplicate.json"
    file_path.write_text(
        json.dumps(rules),
        encoding="utf-8"
    )

    with pytest.raises(ValueError, match="Duplicate rule ID"):
        load_rules(file_path)


def test_invalid_regex(tmp_path):
    rules = load_rules()
    rules[0]["pattern"] = "["

    file_path = tmp_path / "bad_regex.json"
    file_path.write_text(
        json.dumps(rules),
        encoding="utf-8"
    )

    with pytest.raises(ValueError, match="Invalid regex"):
        load_rules(file_path)
