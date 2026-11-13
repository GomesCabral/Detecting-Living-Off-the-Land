# Week 2 Hafi Detection Work — Completion and Validation Report

## Summary

Week 2 detection work is now integrated in this shared project. The app detector covers PowerShell encoded/hidden execution and dynamic expressions, Office-to-interpreter parent-child launches, Certutil retrieval/decode, Bitsadmin transfers, Mshta, Regsvr32, Rundll32, service paths, WMI consumers, and PowerShell 4104 script-block indicators. Findings include a rule ID, severity, ATT&CK technique, and explanation.

The project also includes 10 experimental Sigma rules and 20 inert synthetic cases: one intended positive and one benign example for each rule. These are logic tests, not production ground truth.
The [browser demo CSV](../../../data/week2_demo_logs.csv) adds 22 inert events for trying multiple tools in the app.

## Requirement checklist

| Requirement | Local status | Evidence and limit |
|---|---|---|
| Test rules against benign activity | Implemented with synthetic paired cases | [Test case CSV](../../../data/metadata/lotl_rule_test_cases.csv) has 10 benign examples. This does not measure a real-world false-positive rate. |
| Labeled positive and negative samples | Complete for the local test pack | 20 rows, 10 intended positives and 10 benign examples across 10 experimental rules. |
| Severity and explanations | Implemented | Detection results and Sigma rules contain High/Medium levels and analyst-facing explanations/false-positive notes. Severity is not a calibrated probability. |
| MITRE ATT&CK mapping | Implemented | Rules and Python findings include applicable ATT&CK technique IDs. |
| Certutil, Mshta, Regsvr32, and other selected tools | Implemented as draft indicators | PowerShell, CMD parent context, Certutil, Bitsadmin, Mshta, Regsvr32, Rundll32, service path, WMI consumer, and PowerShell 4104 have rule coverage. |
| Parent-child process context | Implemented as a draft | Detects Office applications directly spawning selected interpreters; approved macros and add-ins may be benign. |
| PowerShell execution patterns | Implemented as draft indicators | Encoded/hidden flags, dynamic-expression calls, and selected 4104 script-block indicators are covered. |
| Sigma rules | Added to the shared project | 10 YAML rules under [rules/sigma](../); all retain `experimental` status. |

## Local validation

From the project root, run:

```powershell
python -m pytest -q
```

Validation result: **13 tests passed; 1 optional Sigma YAML test skipped** because PyYAML is not installed in the default Python environment. The paired-case test calls the local detector with each synthetic record and asserts all 10 intended positives match their expected rule and all 10 benign examples remain unmatched. The browser demo also produces 11 indicators from 22 events. Separately, all 10 Sigma files were parsed and checked for experimental status and valid severity using the available PyYAML environment.

The local Python detector and Sigma selectors are separate implementations. The synthetic cases provide a regression check for the Python detector, not proof that a backend will produce the same alerts.

## Remaining team validation

The following work requires team decisions or representative telemetry:

1. Confirm source-field mappings and choose/version the Sigma backend.
2. Convert and execute Sigma rules in that backend, then compare alerts with source events.
3. Review false positives and false negatives on representative benign and event-labeled attack data.
4. Tune severity and document any allowlists with owner, rationale, and expiry.
5. Report metrics only when labels and evaluation splits support them.

Until those steps are complete, keep the rules experimental. Do not execute attack simulations on production endpoints; use inert fixtures or an approved isolated lab.

## Related files

- [Project README](../../../README.md)
- [Week 2 detection matrix](lolbin_detection_matrix.md)
- [Synthetic cases](../../../data/metadata/lotl_rule_test_cases.csv)
- [Sigma rules](../)
- [Research and telemetry plan](../../../docs/lotl_research_and_detection_plan.md)
- [Detector implementation](../../../src/detector.py)
- [Week 2 tests](../../../tests/test_week2_detection.py)
