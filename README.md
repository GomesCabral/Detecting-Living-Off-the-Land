
# Threat Hunting — Living Off the Land

## Project Overview

A Python-based threat hunting application designed
to identify suspicious Windows command-line activity
involving legitimate operating system tools.

The application combines custom JSON detection rules
with a lightweight Sigma rule evaluation engine.

## Problem Statement

Attackers can abuse legitimate Windows tools to
perform malicious activities while avoiding
traditional security controls.

These techniques are commonly referred to as
Living Off the Land (LOTL).

## Target Users

- SOC Analysts
- Threat Hunters
- Cybersecurity Students
- Incident Response Teams

## Features

- CSV and JSON log ingestion
- File size and format validation
- Log normalization
- JSON-based detection rules
- Lightweight Sigma rule evaluation
- Alert deduplication
- Detection engine provenance
- MITRE ATT&CK technique mapping
- Interactive Streamlit dashboard
- Severity, computer and technique filters
- Alert investigation
- CSV export with formula injection mitigation
- Automated unit and integration tests

## Architecture

Input Logs (CSV / JSON)
        |
File Validation
        |
Log Loader
        |
Normalization
        |
JSON Engine + Sigma Engine
        |
Alert Consolidation
        |
Statistics and Visualizations
        |
Streamlit Dashboard
        |
CSV Export

## Supported Input Fields

Required fields:

- timestamp
- computer
- user
- command_line

Optional field:

- Image

The Image field is required by the current
Sigma PowerShell detection rule.

Alternative field names such as TimeCreated,
ComputerName, UserName and CommandLine
are normalized automatically.

## Detection Coverage

| Behavior | MITRE ATT&CK |
|----------|--------------|
| PowerShell Encoded Command | T1059.001 |
| Certutil URL Cache | T1105 |
| MSHTA Remote Activity | T1218.005 |
| Regsvr32 Remote Activity | T1218.010 |

## Technologies

- Python 3.11
- Pandas
- Streamlit
- Plotly
- PyYAML
- Pytest
- JSON
- Sigma

## Installation

Create a virtual environment:

    python -m venv .venv

Install dependencies on Windows:

    .\.venv\Scripts\python.exe -m pip install -r requirements.txt

## Running the Application

    .\.venv\Scripts\python.exe -m streamlit run app.py

Open:

    http://localhost:8501

Upload a supported CSV or JSON file and select
the desired detection engine.

## Running Tests

    .\.venv\Scripts\python.exe -m pytest -v

## Evaluation

The data/evaluation directory contains synthetic
datasets used to validate:

- Suspicious and benign activity
- Alternative column names
- Missing fields
- Invalid file structures
- Detection engine behavior

## Security Considerations

- Uploaded files are limited to 10 MB.
- Command lines are analyzed as text, not executed.
- CSV exports include formula injection mitigation.
- Missing fields generate warnings or validation errors.
- Original source logs should be preserved separately.

## Limitations

- The application does not replace a full SIEM.
- Detection coverage depends on the available rules.
- Only a subset of Sigma syntax is supported.
- Alerts indicate suspicious behavior, not proof
  of malicious activity.
- JSON Lines and deeply nested event structures
  are not currently supported.
- The application performs file-based analysis,
  not continuous real-time monitoring.

## Project Team

- Pedro — Detection Engine
- Hafidh — Log Ingestion and Normalization
- Igor — Dashboard and Visualization

## Educational Purpose

This project was developed as a cybersecurity
academy capstone to demonstrate threat hunting,
log analysis and detection engineering concepts.
