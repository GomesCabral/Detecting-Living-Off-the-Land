import json
import re
from pathlib import Path


DEFAULT_RULES_PATH = (
    Path(__file__).resolve().parent.parent
    / "rules"
    / "detection_rules.json"
)


def load_rules(file_path=DEFAULT_RULES_PATH):
    try:
        with open(file_path, 'r', encoding="utf-8") as file:
            rules = json.load(file)

    except FileNotFoundError as error:
        raise ValueError("Rules file not found.") from error

    except json.JSONDecodeError as error:
        raise ValueError("Invalid JSON rules file.") from error

    if not isinstance(rules, list):
        raise ValueError("Rules must be a JSON list.")

    required_fields = {
        "id", "name", "description", "severity",
        "mitre_technique", "enabled", "pattern"
    }

    rule_ids = set()

    for rule in rules:
        if not isinstance(rule, dict):
            raise ValueError("Each rule must be an object.")

        missing = required_fields - rule.keys()

        if missing:
            raise ValueError(
                f"Rule is missing fields: {sorted(missing)}"
            )

        if not isinstance(rule["id"], str) or not rule["id"]:
            raise ValueError("Rule ID must be a non-empty string.")

        if rule["id"] in rule_ids:
            raise ValueError(f"Duplicate rule ID: {rule['id']}")

        rule_ids.add(rule["id"])

        for field in (
            "name", "description", "severity",
            "mitre_technique", "pattern"
        ):
            if not isinstance(rule[field], str):
                raise ValueError(
                    f"Rule {rule['id']}: {field} must be text."
                )

        if not isinstance(rule["enabled"], bool):
            raise ValueError(
                f"Rule {rule['id']}: enabled must be boolean."
            )

        try:
            re.compile(rule["pattern"], re.IGNORECASE)
        except re.error as error:
            raise ValueError(
                f"Invalid regex in rule {rule['id']}: {error}"
            ) from error

    return rules
