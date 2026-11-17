import pandas as pd

def filter_alerts(
    alerts_df,
    severity = "All",
    computer = "All",
    technique = "All"
):
    filtered = alerts_df.copy()

    if filtered.empty:
        return filtered

    if severity != "All":
        filtered = filtered[
            filtered["severity"] == severity
        ]

    if computer != "All":
        filtered = filtered[
            filtered["computer"] == computer
        ]

    if technique != "All":
        filtered = filtered[
            filtered["mitre_technique"] == technique
        ]

    return filtered