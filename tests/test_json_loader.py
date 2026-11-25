import json

import pytest

from src.json_loader import load_json


def test_valid_json_file():
    logs = load_json("data/windows_logs.json")

    assert len(logs) == 4
    assert "command_line" in logs.columns
    assert "Image" in logs.columns


def test_json_column_normalization():
    logs = load_json("data/windows_logs.json")

    assert "timestamp" in logs.columns
    assert "computer" in logs.columns
    assert "user" in logs.columns


def test_json_null_values():
    logs = load_json("data/windows_logs.json")

    assert logs.iloc[3]["user"] == "Unknown"
    assert logs.iloc[3]["command_line"] == ""


def test_invalid_json(tmp_path):
    path = tmp_path / "invalid.json"
    path.write_text("{invalid", encoding="utf-8")

    with pytest.raises(ValueError, match="Invalid JSON"):
        load_json(path)


def test_json_missing_columns(tmp_path):
    path = tmp_path / "missing.json"

    data = [
        {
            "timestamp": "2026-11-17",
            "computer": "PC-01"
        }
    ]

    path.write_text(
        json.dumps(data),
        encoding="utf-8"
    )

    with pytest.raises(
        ValueError,
        match="Missing required columns"
    ):
        load_json(path)


def test_json_empty_events(tmp_path):
    path = tmp_path / "empty.json"

    path.write_text(
        json.dumps({"events": []}),
        encoding="utf-8"
    )

    with pytest.raises(
        ValueError,
        match="contains no events"
    ):
        load_json(path)
