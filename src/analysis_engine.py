
from pathlib import Path

from src.detector import analyze_command
from src.rule_loader import load_rules
from src.sigma_engine import (
    load_sigma_rule,
    evaluate_sigma_rule
)


SIGMA_RULES_DIR = (
    Path(__file__).resolve().parent.parent
    / "rules"
    / "sigma"
)


def load_sigma_rules():
    rules = []

    for path in sorted(SIGMA_RULES_DIR.glob("*.yml")):
        rule = load_sigma_rule(path)
        rules.append(rule)

    return rules

def prepare_sigma_event(row):
    event = row.to_dict()

    event["CommandLine"] = str(
        event.get("command_line", "")
    )

    if "Image" not in event:
        event["Image"] = ""

    return event



def analyze_logs(logs, mode="Both"):
    if mode not in ("JSON", "Sigma", "Both"):
        raise ValueError("Invalid detection mode.")

    alerts = []

    json_rules = (
        load_rules()
        if mode in ("JSON", "Both")
        else []
    )

    sigma_rules = (
        load_sigma_rules()
        if mode in ("Sigma", "Both")
        else []
    )

    for event_number, (_, row) in enumerate(
        logs.iterrows(), start=1
    ):
        event_id = f"EVT-{event_number:05d}"
        command = row.get("command_line", "")

        if not isinstance(command, str):
            command = ""

        event_alerts = []

        if mode in ("JSON", "Both"):
            for detection in analyze_command(
                command, json_rules
            ):
                event_alerts.append({
                    "engine": "JSON",
                    "rule_id": detection["rule_id"],
                    "detection": detection["detection"],
                    "severity": detection["severity"],
                    "mitre_technique": detection["mitre_technique"]
                })

        if mode in ("Sigma", "Both"):
            event = prepare_sigma_event(row)

            for rule in sigma_rules:
                if evaluate_sigma_rule(event, rule):
                    technique = next(
                        (
                            tag.replace("attack.", "").upper()
                            for tag in rule.get("tags", [])
                            if tag.startswith("attack.t")
                        ),
                        "Unknown"
                    )

                    event_alerts.append({
                        "engine": "Sigma",
                        "rule_id": rule.get("id", ""),
                        "detection": rule.get("title", ""),
                        "severity": rule.get(
                            "level", "medium"
                        ).capitalize(),
                        "mitre_technique": technique
                    })

        unique_alerts = {}

        for alert in event_alerts:
            key = (
                alert["detection"].lower(),
                alert["mitre_technique"]
            )

            if key not in unique_alerts:
                unique_alerts[key] = {
                    **alert,
                    "engines": [alert["engine"]],
                    "rule_ids": [alert["rule_id"]]
                }
            else:
                existing = unique_alerts[key]

                if alert["engine"] not in existing["engines"]:
                    existing["engines"].append(
                        alert["engine"]
                    )

                if alert["rule_id"] not in existing["rule_ids"]:
                    existing["rule_ids"].append(
                        alert["rule_id"]
                    )

        for alert in unique_alerts.values():
            alert_number = len(alerts) + 1

            alerts.append({
                "alert_id": f"ALT-{alert_number:05d}",
                "event_id": event_id,
                "event_index": event_number - 1,
                "timestamp": row.get("timestamp", ""),
                "computer": row.get("computer", ""),
                "user": row.get("user", ""),
                "command_line": command,
                "detection": alert["detection"],
                "severity": alert["severity"],
                "mitre_technique": alert["mitre_technique"],
                "engines": ", ".join(alert["engines"]),
                "rule_ids": ", ".join(alert["rule_ids"])
            })

    return alerts
