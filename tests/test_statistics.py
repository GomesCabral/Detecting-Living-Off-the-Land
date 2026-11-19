
import pandas as pd

from src.statistics import calculate_statistics


def test_total_events():

    logs = pd.DataFrame({
        "command_line": ["whoami", "notepad.exe"]
    })

    stats = calculate_statistics(logs, [])

    assert stats["total_events"] == 2


def test_no_alerts():

    logs = pd.DataFrame({
        "command_line": ["whoami"]
    })

    stats = calculate_statistics(logs, [])

    assert stats["total_alerts"] == 0
    assert stats["alerted_events"] == 0
    assert stats["detection_rate"] == 0


def test_detection_rate():

    logs = pd.DataFrame({
        "command_line": [
            "powershell.exe -enc TEST",
            "notepad.exe"
        ]
    })

    alerts = [
        {
            "event_id": "EVT-00001",
            "computer": "PC-01"
        }
    ]

    stats = calculate_statistics(logs, alerts)

    assert stats["detection_rate"] == 50.0


def test_duplicate_event_alerts():

    logs = pd.DataFrame({
        "command_line": ["test", "whoami"]
    })

    alerts = [
        {
            "event_id": "EVT-00001",
            "computer": "PC-01"
        },
        {
            "event_id": "EVT-00001",
            "computer": "PC-01"
        }
    ]

    stats = calculate_statistics(logs, alerts)

    assert stats["total_alerts"] == 2
    assert stats["alerted_events"] == 1
    assert stats["detection_rate"] == 50.0


def test_affected_computers():

    logs = pd.DataFrame({
        "command_line": ["test1", "test2", "test3"]
    })

    alerts = [
        {
            "event_id": "EVT-00001",
            "computer": "PC-01"
        },
        {
            "event_id": "EVT-00002",
            "computer": "PC-01"
        },
        {
            "event_id": "EVT-00003",
            "computer": "PC-02"
        }
    ]

    stats = calculate_statistics(logs, alerts)

    assert stats["affected_computers"] == 2


def test_empty_logs():

    logs = pd.DataFrame()

    stats = calculate_statistics(logs, [])

    assert stats["total_events"] == 0
    assert stats["detection_rate"] == 0
