
import io
import pandas as pd

from src.exporter import export_alerts_csv

def test_export_csv():
    alerts = pd.DataFrame([
        {
            "alert_id": "ALT-00001",
            "computer": "PC-01",
            "severity": "High"
        }
    ])

    result = export_alerts_csv(alerts)

    assert isinstance(result, bytes)

    exported = pd.read_csv(io.BytesIO(result))

    assert len(exported) == 1
    assert exported.iloc[0]["computer"] == "PC-01"

def test_export_empty_csv():
    alerts = pd.DataFrame(
        columns=["alert_id", "computer", "severity"]
    )

    result = export_alerts_csv(alerts)

    exported = pd.read_csv(io.BytesIO(result))

    assert exported.empty
    assert list(exported.columns) == [
        "alert_id",
        "computer",
        "severity"
    ]