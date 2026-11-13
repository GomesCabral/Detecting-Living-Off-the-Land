# Week 2 LOLBins Detection Matrix

The matrix reflects the 10 experimental Sigma rules under `rules/sigma/`. Severity values below are the rules' current Sigma `level` values, not measured risk scores or proof of malicious activity.

| Rule / tool | Detection hypothesis | Required telemetry | Sigma level | ATT&CK mapping | Benign explanations / validation notes |
|---|---|---|---|---|---|
| PowerShell process creation | Encoded-command or hidden-window flags | Sysmon Event 1: `Image`, `CommandLine` | Medium | T1059.001 | Approved deployment/management scripts; review script content and parent. |
| PowerShell script block | Script-block content contains high-risk execution indicators | PowerShell Operational Event 4104 and `ScriptBlockText` | Medium | T1059.001 | Admin scripts; blocks may be fragmented and the corpus coverage is sparse. |
| Office-to-interpreter parent-child | Office app directly launches CMD, PowerShell, or a script host | Sysmon Event 1: `Image`, `ParentImage` | High | T1059 (parent technique) | Approved macros, add-ins, and document automation; inspect full process tree and document provenance. |
| Certutil | URL-cache retrieval or decode operation | Sysmon Event 1: `Image`, `CommandLine` | Medium | T1105, T1140 | PKI maintenance and distribution; verify source, destination, signer, and follow-on process. |
| Bitsadmin | Transfer/add-file operation with HTTP(S) source | Sysmon Event 1: `Image`, `CommandLine` | Medium | T1197, T1105 | Approved background transfer; process creation does not prove a BITS job completed. Correlate BITS logs. |
| Mshta | Inline script protocol or remote URL in command line | Sysmon Event 1: `Image`, `CommandLine` | High | T1218.005 | Approved legacy HTA; verify origin, signer, and network activity. |
| Regsvr32 | Remote scriptlet load | Sysmon Event 1: `Image`, `CommandLine` | High | T1218.010 | Software registration; review target scriptlet and process lineage. |
| Rundll32 | Script or URL proxy-execution indicators | Sysmon Event 1: `Image`, `CommandLine` | Medium | T1218.011 | Control Panel and shell integrations; inspect DLL, export, signer, and parent. |
| Service binary path | New service points to a user-writable binary path | System Event 7045: provider and `ImagePath` | Medium | T1543.003 | Approved installers/updaters; validate service owner, path ACLs, and change record. |
| WMI event consumer | Consumer destination references an interpreter or writable path | Sysmon Event 20: `EventID`, `Destination`; correlate Events 19 and 21 | Medium | T1546.003 | Monitoring/administration; one consumer record alone does not establish an active subscription. |

## Severity interpretation

The rules use canonical Sigma levels (`medium` or `high`). High means prioritize analyst review because the selector combines higher-risk behavior; medium means investigate with surrounding context. Neither level is a calibrated probability or a claim that the event is malicious. Sigma levels can be retuned after evaluation on representative benign and attack telemetry.

## Labeled test cases and false-positive checks

The canonical fixture is [lotl_rule_test_cases.csv](../../../data/metadata/lotl_rule_test_cases.csv). It contains one synthetic positive and one synthetic benign case for each of the 10 rules (20 cases total). Cases are inert event records; no attack commands are run. The test suite checks expected match/no-match results against the local detector; optional PyYAML checks validate rule structure, not backend matches. These pairs demonstrate logic behavior, but are too small and artificial to estimate false-positive rates.

## Process lineage and attack simulation boundary

The parent-child rule checks Office applications (`WINWORD`, `EXCEL`, `POWERPNT`, `OUTLOOK`) directly starting a selected command or script interpreter. Simulation coverage is represented by inert labeled events only; do not execute attack-like commands on a production endpoint. For real validation, use an isolated lab and the team's approved simulation procedure, then retain telemetry, backend version, field mapping, and event-level labels.

## Limitations

- Rule fields assume provisional Sysmon/Windows mappings; confirm them with the team's chosen backend.
- Event 4104, 7045, and WMI telemetry is sparse in the available corpus.
- Public attack samples lack representative benign prevalence and event-level ground truth.
- A rule match is a triage lead. Do not report precision, recall, or production false-positive rates from these synthetic cases.
