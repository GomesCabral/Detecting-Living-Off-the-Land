# Week 2 — Detection Rules and Attack Simulation

This folder is the handoff index for Hafi's Week 2 detection and attack-simulation work in this shared project.

## Deliverables

- [Detection matrix](lolbin_detection_matrix.md) — tool coverage, telemetry, severity, ATT&CK mapping, and caveats.
- [Completion and validation report](week2_complete_summary.md) — requirement-by-requirement status and test evidence.
- [Labeled synthetic cases](../../../data/metadata/lotl_rule_test_cases.csv) — 20 inert positive/benign event examples for 10 experimental rules.
- [Multi-tool browser demo](../../../data/week2_demo_logs.csv) — 22 inert events for viewing the rules in the dashboard.
- [Sigma rules](../) — 10 experimental rules, with rationale and false-positive notes in each rule.
- [Research and telemetry plan](../../../docs/lotl_research_and_detection_plan.md) — source prerequisites, limitations, and evaluation boundaries.
- [Week 2 detector and sample tests](../../../tests/test_week2_detection.py).

## Verify

From this project folder, run:

```powershell
python -m pytest -q
```

The checked-in case tests compare the expected positive/benign labels with the local detector. They do not execute LOLBins, run a Sigma backend, or measure production false-positive rates. Sigma YAML parsing is an optional test that requires PyYAML.

## Status and boundaries

The local research, rule drafts, synthetic examples, ATT&CK tags, severity levels, and regression checks are included for handoff. The rules remain `experimental`: team approval of the schema/backend, conversion and execution in the agreed backend, and evaluation on representative labeled telemetry are still required before claiming operational validation.

Week 1 remains the separate MVP baseline with the `PS-001` PowerShell rule.
