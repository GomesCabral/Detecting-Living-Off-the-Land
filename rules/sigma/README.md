# Sigma Rule Drafts

Rules in this folder are **experimental draft hypotheses**, not validated detections. There are initial rules for PowerShell script content, Sysmon PowerShell process creation, Office-to-interpreter parent-child behavior, Certutil, Bitsadmin, Mshta, Regsvr32, Rundll32, service installation, and WMI consumers. The process creation rules assume Sysmon Event ID 1 fields (`Image`, `CommandLine`, `ParentImage`) as a provisional mapping. The actual backend mapping is still open, and handoff inventory counts are sparse for several event types.

See `docs/lotl_research_and_detection_plan.md` for research, prerequisites, ATT&CK hypotheses, false-positive context, and scope limits. Synthetic positive and benign example cases are in `data/metadata/lotl_rule_test_cases.csv`; they are inert examples and do not represent measured results from the public corpus.

Before running or promoting a rule:

1. Confirm the source channel/provider and field names in the agreed normalized schema.
2. Select the backend with Pedro and record its version, configuration, and field mappings.
3. Review alert examples against the source events and add benign examples for tuning.
4. Record TP/FP/FN/TN only where ground truth supports them; report coverage and label limits separately.
5. Do not tune against held-out or unseen splits.

The rules intentionally use narrow, inspectable indicators as starting points. Their presence does not prove malicious activity; investigate context and expected administration.

The Week 2 Hafi task index, detection matrix, and completion report are in [week2/](week2/README.md).
