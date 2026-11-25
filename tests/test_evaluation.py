import pytest

from src.loader import load_csv
from src.json_loader import load_json
from src.analysis_engine import analyze_logs

DATA_DIR = "data/evaluation"

def test_mixed_logs():
    logs = load_csv(
        f"{DATA_DIR}/mixed_logs.csv"
    )

    alerts = analyze_logs(logs, mode="Both")

    assert len(logs) == 10
    assert len(alerts) == 5

def test_mixed_logs_correct_events():
    logs = load_csv(
        f"{DATA_DIR}/mixed_logs.csv"
    )

    alerts = analyze_logs(logs, mode="Both")

    detected_events = {
        alert["event_id"]
        for alert in alerts
    }

    assert detected_events == {
        "EVT-00002",
        "EVT-00004",
        "EVT-00006",
        "EVT-00008",
        "EVT-00010"
    }

def test_clean_logs():
    logs = load_csv(
        f"{DATA_DIR}/clean_logs.csv"
    )

    alerts = analyze_logs(logs, mode="Both")

    assert len(logs) == 5
    assert alerts == []

def test_unknown_json():
    logs = load_json(
        f"{DATA_DIR}/unknown_logs.json"
    )

    alerts = analyze_logs(logs, mode="Both")

    assert len(logs) == 4
    assert len(alerts) == 2

def test_invalid_logs():
    with pytest.raises(
        ValueError,
        match="Missing required columns"
    ):
        load_csv(
            f"{DATA_DIR}/invalid_logs.csv"
        )

def test_missing_image_json():
    logs = load_csv(
        f"{DATA_DIR}/missing_image.csv"
    )

    alerts = analyze_logs(logs, mode="JSON")

    assert len(alerts) == 2

def test_missing_image_sigma():
    logs = load_csv(
        f"{DATA_DIR}/missing_image.csv"
    )

    alerts = analyze_logs(logs, mode="Sigma")

    assert alerts == []

def test_missing_image_both():
    logs = load_csv(
        f"{DATA_DIR}/missing_image.csv"
    )

    alerts = analyze_logs(logs, mode="Both")

    assert len(alerts) == 2