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