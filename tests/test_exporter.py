
import io
import pandas as pd

from src.exporter import (
    export_alerts_csv,
    sanitize_csv_value
)


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


def test_csv_formula_sanitization():
    assert sanitize_csv_value("=1+1") == "'=1+1"


def test_csv_at_prefix():
    assert sanitize_csv_value("@SUM(A1:A2)") == (
        "'@SUM(A1:A2)"
    )


def test_csv_safe_value():
    assert sanitize_csv_value("powershell.exe") == (
        "powershell.exe"
    )


def test_csv_leading_spaces():
    assert sanitize_csv_value("  =1+1") == (
        "'  =1+1"
    )
