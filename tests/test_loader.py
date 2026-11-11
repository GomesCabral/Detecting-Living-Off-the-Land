import pandas as pd
import pytest

from src.loader import validate_columns


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