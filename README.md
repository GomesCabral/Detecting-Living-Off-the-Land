# Threat Hunting: Living Off the Land — Week 1 MVP

**Team:** Pedro (detection), Hafidh (data ingestion/normalization), Igor (Streamlit interface).

This is a **working Week 1 prototype**, not the completed capstone and not a SIEM. It accepts compatible CSV/JSON Windows-style logs, normalizes several column aliases, runs one PowerShell indicator rule, and displays findings with evidence. All bundled events are synthetic.

## Installation (Python 3.10+)

```bash
python -m venv .venv
# Windows PowerShell:
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
pytest -q
streamlit run app.py
```

CLI demonstration:

```bash
python cli.py data/samples/suspicious_events.csv
python cli.py data/samples/normal_events.csv
```

The `PS-001` detection conditions, expected results, and limitations are documented in [docs/detection_logic.md](docs/detection_logic.md).

## Responsibilities and acceptance

- **Pedro:** `src/detections/powershell.py`, `src/pipeline.py`, `cli.py`; verify suspicious indicator detected and benign PowerShell not flagged.
- **Hafidh:** `src/loader.py`, `src/normalizer.py`, `docs/data_schema.md`, `data/samples/`; verify CSV, JSON, aliases, missing fields.
- **Igor:** `app.py`; verify upload, preview, mapping, run, findings, download, and error messages.

## Known limits

- Week 1 only: one rule for suspicious PowerShell indicators. PsExec/WMI, service accounts, baselines, correlation, and ATT&CK investigation timeline are **not implemented yet**.
- Accepts only supported CSV/JSON structures. Does not parse `.evtx`, nested arbitrary SIEM exports, or arbitrary security products.
- Field mapping handles name differences, not semantic incompatibility. Missing fields cause a validation error or detection limitation.
- The first rule checks indicators, not malicious intent. False positives and missed attacks are possible.
- The dashboard is local; do not expose it to the public Internet.



