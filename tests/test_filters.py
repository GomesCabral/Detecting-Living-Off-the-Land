import pandas as pd

from src.filters import filter_alerts

def sample_alerts():
    return pd.DataFrame([
        {
            "severity": "High",
            "computer": "PC-01",
            "mitre_technique": "T1059.001"
        },
        {
            "severity": "Medium",
            "computer": "PC-02",
            "mitre_technique": "T1105"
        },
        {
            "severity": "High",
            "computer": "PC-03",
            "mitre_technique": "T1218.005"
        }
    ])

def test_filter_by_severity():
    result = filter_alerts(
        sample_alerts(),
        severity="High"
    )

    assert len(result) == 2

def test_filter_by_computer():
    result = filter_alerts(
        sample_alerts(),
        computer="PC-02"
    )

    assert len(result) == 1
    assert result.iloc[0]["severity"] == "Medium"

def test_filter_by_technique():
    result = filter_alerts(
        sample_alerts(),
        technique="T1059.001"
    )

    assert len(result) == 1

def test_combined_filters():
    result = filter_alerts(
        sample_alerts(),
        severity="High",
        computer="PC-01",
        technique="T1059.001"
    )

    assert len(result) == 1

def test_no_matching_alerts():
    result = filter_alerts(
        sample_alerts(),
        computer="PC-99"
    )

    assert result.empty