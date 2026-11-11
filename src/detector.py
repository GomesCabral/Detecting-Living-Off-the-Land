def detect_powershell(command):
    command = str(command).lower()

    if "powershell" in command and "-enc" in command:
        return "Suspicious PowerShell Encoded Command"

    return None


def detect_certutil(command):
    command = str(command).lower()

    if "certutil" in command and "-urlcache" in command:
        return "Suspicious Certutil Download"

    return None


def detect_mshta(command):
    command = str(command).lower()

    if "mshta" in command and (
        "http://" in command or "https://" in command
    ):
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
