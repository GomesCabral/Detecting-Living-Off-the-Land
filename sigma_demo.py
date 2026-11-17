
from src.loader import load_csv
from src.sigma_engine import (
    load_sigma_rule,
    evaluate_sigma_rule
)


rule = load_sigma_rule(
    "rules/sigma/powershell_encoded.yml"
)

logs = load_csv("data/sigma_test_logs.csv")

print("=== SIGMA DETECTION RESULTS ===")

for _, row in logs.iterrows():
    event = row.to_dict()

    # O CSV usa command_line, mas a regra usa CommandLine.
    event["CommandLine"] = event["command_line"]

    if evaluate_sigma_rule(event, rule):
        print(f"ALERT: {rule['title']}")
        print(f"Computer: {event['computer']}")
        print(f"Command: {event['CommandLine']}")
        print("---")
