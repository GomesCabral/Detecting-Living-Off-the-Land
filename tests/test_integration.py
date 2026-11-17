import io
import json
 
import pandas as pd
 
from src.file_validator import validate_file
from src.json_loader import load_json
from src.analysis_engine import analyze_logs
from src.filters import filter_alerts
from src.exporter import export_alerts_csv
 
 
def test_complete_analysis_pipeline(tmp_path):
    path = tmp_path / "new_windows_logs.json"
 
    events = {
        "events": [
            {
                "TimeCreated": "2026-11-17 10:00:00",
                "ComputerName": "PC-01",
                "UserName": "Admin",
                "Image": (
                    r"C:\Windows\System32\powershell.exe"
                ),
                "CommandLine": (
                    "powershell.exe -enc SQBFAFgA"
                )
            },
            {
                "TimeCreated": "2026-11-17 10:05:00",
                "ComputerName": "PC-02",
                "UserName": "Pedro",
                "Image": (
                    r"C:\Windows\System32\notepad.exe"
                ),
                "CommandLine": "notepad.exe"
            }
        ]
    }
 
    path.write_text(
        json.dumps(events),
        encoding="utf-8"
    )
 
    extension = validate_file(path)
 
    assert extension == ".json"
 
    logs = load_json(path)
 
    assert len(logs) == 2
 
    alerts = analyze_logs(logs, mode="Both")
 
    assert len(alerts) == 1
    assert alerts[0]["computer"] == "PC-01"
    assert alerts[0]["engines"] == "JSON, Sigma"
 
    alerts_df = pd.DataFrame(alerts)
 
    filtered = filter_alerts(
        alerts_df,
        severity="High",
        computer="PC-01",
        technique="T1059.001"
    )
 
    assert len(filtered) == 1
 
    exported_bytes = export_alerts_csv(filtered)
 
    exported_df = pd.read_csv(
        io.BytesIO(exported_bytes)
    )
 
    assert len(exported_df) == 1
    assert exported_df.iloc[0]["computer"] == "PC-01"

 
