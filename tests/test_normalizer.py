import pandas as pd

from src.normalizer import normalize_logs


def test_normalize_columns_names():
    df = pd.DataFrame({
        "TimeCreated": ["2026-11-09 10:00:00"],
        "ComputerName": ["PC-01"],
        "UserName": ["Pedro"],
        "CommandLine": ["whoami"]
    })

    result = normalize_logs(df)

    assert "timestamp" in result.columns
    assert "computer" in result.columns
    assert "user" in result.columns
    assert "command_line" in result.columns


def test_remove_column_spaces():
    df = pd.DataFrame({
        "  ComputerName  ": ["PC-01"]
    })

    result = normalize_logs(df)

    assert "computer" in result.columns


def test_case_insensitive_columns():
    df = pd.DataFrame({
        "TIMECREATED": ["2026-11-17"],
        "COMPUTERNAME": ["PC-01"],
        "USERNAME": ["Admin"],
        "COMMANDLINE": ["whoami"]
    })

    result = normalize_logs(df)

    assert "timestamp" in result.columns
    assert "computer" in result.columns
    assert "user" in result.columns
    assert "command_line" in result.columns


def test_missing_command_values():
    df = pd.DataFrame({
        "command_line": [None, "notepad.exe"]
    })

    result = normalize_logs(df)

    assert result.iloc[0]["command_line"] == ""


def test_duplicate_normalized_columns():
    df = pd.DataFrame({
        "CommandLine": ["whoami"],
        "command_line": ["notepad.exe"]
    })

    import pytest

    with pytest.raises(
        ValueError,
        match="Duplicate columns"
    ):
        normalize_logs(df)
