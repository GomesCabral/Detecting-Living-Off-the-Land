import re

def detect_powershell(command):
    if not isinstance(command, str):
        return None

    pattern = (
        r"^\s*(?:powershell|powershell\.exe|pwsh|pwsh\.exe)"
        r"\s+.*?-(?:enc|encodedcommand)\b\s+\S+"
    )

    if re.search(pattern, command, re.IGNORECASE):
        return "Suspicious PowerShell Encoded Command"

    return None

def detect_certutil(command):
    if not isinstance(command, str):
        return None

    pattern = (
        r"^\s*certutil(?:\.exe)?\s+"
        r".*?-urlcache\b"
    )

    if re.search(pattern, command, re.IGNORECASE):
        return "Suspicious Certutil Download"

    return None

def detect_mshta(command):
    if not isinstance(command, str):
        return None

    pattern = (
        r"^\s*mshta(?:\.exe)?\s+"
        r"https?://\S+"
    )

    if re.search(pattern, command, re.IGNORECASE):
        return "Suspicious MSHTA Remote Execution"

    return None

def analyze_command(command):
    detections = []

    rules = [
        (
            detect_powershell,
            "High",
            "T1059.001"
        ),
        (
            detect_certutil,
            "Medium",
            "T1105"
        ),
        (
            detect_mshta,
            "High",
            "T1218.005"
        )
    ]

    for rule, severity, technique in rules:
        result = rule(command)

        if result is not None:
            detections.append({
                "detection": result,
                "severity": severity,
                "mitre_technique": technique
            })

    return detections