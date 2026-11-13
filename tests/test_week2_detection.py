import csv
from pathlib import Path

import pytest

from src.detector import analyze_command
from src.loader import load_csv


# Hafi Week 2: assert paired synthetic cases against the shared-project detector.
ROOT = Path(__file__).resolve().parents[1]
CASE_FILE = ROOT / "data" / "metadata" / "lotl_rule_test_cases.csv"
DEMO_FILE = ROOT / "data" / "week2_demo_logs.csv"
SIGMA_RULES = ROOT / "rules" / "sigma"
EXPECTED_RULE_IDS = {
    "sysmon_powershell_encoded_or_hidden_process": "PS-001",
    "windows_sysmon_suspicious_interpreter_parent": "CMD-001",
    "windows_sysmon_certutil_transfer_or_decode": "CERT-001",
    "windows_sysmon_bitsadmin_remote_transfer": "BITS-001",
    "windows_sysmon_mshta_script_or_remote_content": "MSHTA-001",
    "windows_sysmon_regsvr32_remote_scriptlet": "REG-001",
    "windows_sysmon_rundll32_proxy_execution": "RUNDLL-001",
    "powershell_4104_suspicious_script_content": "PS-003",
    "windows_7045_service_binary_user_writable_path": "SVC-001",
    "sysmon_20_suspicious_wmi_consumer": "WMI-001",
}


def test_labeled_week2_cases_match_expected_detector_outcomes():
    with CASE_FILE.open(encoding="utf-8-sig", newline="") as stream:
        cases = list(csv.DictReader(stream))
    assert len(cases) == 20

    for case in cases:
        expected_rule = EXPECTED_RULE_IDS[case["expected_rule"]]
        detections = analyze_command(
            case["command_line"],
            parent_process=case["parent_process_name"],
            event=case,
        )
        matched_rules = {item["rule_id"] for item in detections}

        if case["event_label"] == "malicious":
            assert matched_rules == {expected_rule}, case["case_id"]
            detection = detections[0]
            assert detection["severity"] in {"High", "Medium"}
            assert detection["mitre_technique"].startswith("T")
            assert detection["explanation"]
        else:
            assert matched_rules == set(), case["case_id"]


def test_encoded_looking_flag_without_powershell_context_is_not_detected():
    assert analyze_command("cmd.exe /c echo -EncodedCommand") == []


def test_powershell_dynamic_expression_is_detected():
    detections = analyze_command('powershell.exe -Command "IEX $payload"')
    assert [item["rule_id"] for item in detections] == ["PS-002"]


def test_week2_demo_csv_runs_through_project_ingestion():
    logs = load_csv(DEMO_FILE)
    detections = []

    for _, row in logs.iterrows():
        detections.extend(
            analyze_command(
                row["command_line"],
                parent_process=row.get("parent_process", ""),
                event=row,
            )
        )

    assert len(logs) == 22
    assert len(detections) == 11
    assert {
        "PS-001", "PS-002", "CMD-001", "CERT-001", "BITS-001",
        "MSHTA-001", "REG-001", "RUNDLL-001", "PS-003", "SVC-001",
        "WMI-001",
    } == {item["rule_id"] for item in detections}


def test_sigma_rule_set_has_parseable_experimental_rules():
    yaml = pytest.importorskip("yaml")
    rule_files = sorted(SIGMA_RULES.rglob("*.yml"))
    assert len(rule_files) == 10

    for rule_file in rule_files:
        rule = yaml.safe_load(rule_file.read_text(encoding="utf-8-sig"))
        assert rule["status"] == "experimental"
        assert rule["level"] in {"medium", "high"}
        assert rule["id"]
        assert rule["detection"]["condition"]
