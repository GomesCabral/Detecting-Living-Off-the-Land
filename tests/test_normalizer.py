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


# Hafi Week 2: cover normalized parent lineage and event-specific evidence.
def test_normalize_week2_parent_and_event_context():
    df = pd.DataFrame({
        "ParentImage": [r"C:\Program Files\Microsoft Office\WINWORD.EXE"],
        "EventID": [20],
        "Destination": [r"C:\ProgramData\helper.ps1"],
        "ScriptBlockText": ["Get-Process"]
    })

    result = normalize_logs(df)

    assert result.loc[0, "parent_process"].endswith("WINWORD.EXE")
    assert result.loc[0, "event_id"] == 20
    assert result.loc[0, "destination"].endswith("helper.ps1")
    assert result.loc[0, "scriptblocktext"] == "Get-Process"