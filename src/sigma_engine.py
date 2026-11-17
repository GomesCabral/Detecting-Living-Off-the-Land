
from pathlib import Path

import yaml


def load_sigma_rule(file_path):
    with open(file_path, "r", encoding="utf-8") as file:
        rule = yaml.safe_load(file)

    if not isinstance(rule, dict):
        raise ValueError("Invalid Sigma rule.")

    if "detection" not in rule:
        raise ValueError("Missing detection section.")

    return rule


def match_field(event, field_expression, expected):
    parts = field_expression.split("|")

    field_name = parts[0]
    modifier = parts[1] if len(parts) > 1 else None

    actual = str(event.get(field_name, "")).lower()

    values = expected if isinstance(expected, list) else [expected]

    for value in values:
        value = str(value).lower()

        if modifier == "contains":
            if value in actual:
                return True

        elif modifier == "endswith":
            if actual.endswith(value):
                return True

        elif modifier is None:
            if actual == value:
                return True

        else:
            raise ValueError(
                f"Unsupported Sigma modifier: {modifier}"
            )

    return False



def match_selection(event, selection):
    if not isinstance(selection, dict):
        raise ValueError("Unsupported selection format.")

    for field_expression, expected in selection.items():
        if not match_field(event, field_expression, expected):
            return False

    return True


def evaluate_sigma_rule(event, rule):
    detection = rule["detection"]
    condition = detection.get("condition", "")

    selections = {
        name: value
        for name, value in detection.items()
        if name != "condition"
    }

    results = {
        name: match_selection(event, selection)
        for name, selection in selections.items()
    }

    names = condition.split(" and ")

    if len(names) != 2:
        raise ValueError(
            "Only two-selection AND conditions are supported."
        )

    if any(name not in results for name in names):
        raise ValueError(
            "Condition references an unknown selection."
        )

    return all(results[name] for name in names)
