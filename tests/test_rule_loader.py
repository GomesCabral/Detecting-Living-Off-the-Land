import json

import pytest

from src.rule_loader import load_rules


def test_load_valid_rules():
    rules = load_rules()

    assert len(rules) == 4
    assert rules[0]["id"] == "LOL-001"


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
