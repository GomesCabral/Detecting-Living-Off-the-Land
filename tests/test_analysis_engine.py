import pandas as pd

from src.analysis_engine import analyze_logs


def sample_logs():
    return pd.DataFrame([
        {
            "timestamp": "2026-11-16 10:00:00",
            "computer": "PC-01",
            "user": "Admin",
            "Image": r"C:\Windows\System32\powershell.exe",
            "command_line": "powershell.exe -enc SQBFAFgA"
        },
        {
            "timestamp": "2026-11-16 10:02:00",
            "computer": "PC-02",
            "user": "Pedro",
            "Image": r"C:\Windows\System32\notepad.exe",
            "command_line": "notepad.exe"
        }
    ])


def test_json_engine():
    alerts = analyze_logs(sample_logs(), mode="JSON")

    assert len(alerts) == 1
    assert alerts[0]["engines"] == "JSON"


def test_sigma_engine():
    alerts = analyze_logs(sample_logs(), mode="Sigma")

    assert len(alerts) == 1
    assert alerts[0]["engines"] == "Sigma"


def test_both_engines_deduplication():
    alerts = analyze_logs(sample_logs(), mode="Both")

    assert len(alerts) == 1


def test_no_alerts():
    logs = pd.DataFrame([
        {
            "timestamp": "2026-11-16 10:00:00",
            "computer": "PC-02",
            "user": "Pedro",
            "Image": r"C:\Windows\System32\notepad.exe",
            "command_line": "notepad.exe"
        }
    ])

    assert analyze_logs(logs, mode="Both") == []



def test_alert_identifiers():
    alerts = analyze_logs(sample_logs(), mode="Both")

    assert len(alerts) == 1
    assert alerts[0]["alert_id"] == "ALT-00001"
    assert alerts[0]["event_id"] == "EVT-00001"

def test_detection_provenance():
    alerts = analyze_logs(sample_logs(), mode="Both")

    assert len(alerts) == 1
    assert alerts[0]["engines"] == "JSON, Sigma"

    assert "LOL-001" in alerts[0]["rule_ids"]