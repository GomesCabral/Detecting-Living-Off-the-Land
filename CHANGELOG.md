# Changelog



## Hafi Week 2 detection work

### Updated

- `src/detector.py`
  - Added indicators for encoded or hidden PowerShell, PowerShell dynamic expressions, Certutil remote retrieval and decoding, Bitsadmin transfers, Mshta script or remote content, Regsvr32 remote scriptlets, and Rundll32 script/URL patterns.
  - Added Office-to-interpreter parent-child context, service binary path checks, WMI consumer checks, and PowerShell 4104 script-block checks.
  - Added rule IDs, severity, ATT&CK technique IDs, and analyst explanations to returned findings.
  - Kept `analyze_command(command)` compatible with the earlier one-argument call.
- `src/normalizer.py`
  - Added aliases for parent process, event ID, service image path, WMI destination, and PowerShell script-block fields.
- `app.py`
  - Passes parent-process and event fields into the detector and displays rule ID, parent context, and explanation with findings.
  - Uses neutral indicator wording in dashboard messages.
- `tests/test_normalizer.py`
  - Added coverage for normalizing the Week 2 parent and event-context fields.
- `README.md`
  - Added project test instructions and links to the Week 2 deliverables and demo CSV.
- `docs/lotl_research_and_detection_plan.md`
  - Updated descriptive wording for indicators and process context.
The changed Python files include comments identifying the Hafi Week 2 contribution.

### Added

- `data/metadata/lotl_rule_test_cases.csv`
  - 20 inert synthetic cases: one intended positive and one benign case for each of 10 detection-rule hypotheses.
- `data/week2_demo_logs.csv`
  - 22 synthetic event rows covering multiple tools and benign examples for a dashboard walkthrough.
- `tests/test_week2_detection.py`
  - Checks the labeled cases against the local detector, verifies the demo CSV through the project loader, and optionally parses the Sigma YAML when PyYAML is installed.
- `rules/sigma/`
  - 10 experimental Sigma YAML rules covering PowerShell, Office-to-interpreter process lineage, Certutil, Bitsadmin, Mshta, Regsvr32, Rundll32, service paths, and WMI consumers.
- `rules/sigma/week2/`
  - Week 2 README, detection matrix, and completion/validation report.
- `rules/sigma/README.md`
  - Rule usage notes and a link to the Week 2 package.

### Validation

- `python -m pytest -q`: 13 passed, 1 optional YAML test skipped because PyYAML is not installed in the default Python environment.
- Parsed and checked all 10 Sigma files using the available PyYAML environment.
- Streamlit AppTest rendered the dashboard without exceptions.
- Browser walkthrough with `data/week2_demo_logs.csv`: 22 events, 11 indicators, and 11 events without indicators.

### Boundaries

- All included test/demo events are synthetic and inert; no Windows commands were executed.
- Sigma rules remain experimental and have not been converted or run in the team's selected backend.
- Production false-positive/false-negative rates and operational severity tuning require representative, labeled telemetry.

