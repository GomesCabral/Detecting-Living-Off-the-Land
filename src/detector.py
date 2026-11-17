
import re

from src.rule_loader import load_rules


def analyze_command(command, rules=None):
    if not isinstance(command, str):
        return []

    if rules is None:
        rules = load_rules()

    detections = []

    for rule in rules:
        if not rule["enabled"]:
            continue

        match = re.search(
            rule["pattern"],
            command,
            re.IGNORECASE
        )

        if match:
            detections.append({
                "rule_id": rule["id"],
                "detection": rule["name"],
                "description": rule["description"],
                "severity": rule["severity"],
                "mitre_technique": rule["mitre_technique"]
            })



    return detections
