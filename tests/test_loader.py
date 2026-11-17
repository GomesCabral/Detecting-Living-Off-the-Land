import pandas as pd
import pytest

from src.loader import validate_columns
from src.loader import validate_logs


def test_valid_columns():
    df = pd.DataFrame({
        "timestamp": ["2026-11-09 10:00:00"],
        "computer": ["PC-01"],
        "user": ["Pedro"],
        "command_line": ["whoami"],
    })

    result = validate_columns(df)

    assert result is True


def test_missing_columns():
    df = pd.DataFrame({
        "timestamp": ["2026-11-09 10:00:00"],
        "computer": ["PC-01"]
    })

    with pytest.raises(ValueError):
        validate_columns(df)


def test_all_commands_empty():
    df = pd.DataFrame({
        "timestamp": ["2026-11-17"],
        "computer": ["PC-01"],
        "user": ["Admin"],
        "command_line": [""]
    })

    with pytest.raises(
        ValueError,
        match="All command_line values are empty"
    ):
        validate_logs(df)
