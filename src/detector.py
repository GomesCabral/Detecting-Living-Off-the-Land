import re


# Hafi Week 2 contribution: add contextual LOLBin and event-based detection rules.
def _has_executable(command, names):
    alternatives = "|".join(re.escape(name) for name in names)
    return bool(
        re.search(
            rf"(?i)(?:^|[\s\\\"/])(?:{alternatives})(?:\.exe)?(?=$|[\s\"])",
            str(command),
        )
    )


def _event_value(event, *names):
    if event is None:
        return ""
    for name in names:
        if name not in event:
            continue
        value = event.get(name, "")
        if value is None:
            continue
        text = str(value)
        if text and text.casefold() != "nan":
            return text
    return ""


def _event_id(event):
    return re.sub(r"\.0$", "", _event_value(event, "event_id", "EventID", "EventCode").strip())


def detect_powershell(command):
    command = str(command)
    if not _has_executable(command, ("powershell", "pwsh")):
        return None

    encoded = re.search(r"(?i)(?:^|\s)-(?:enc|encodedcommand)\b", command)
    hidden = re.search(r"(?i)(?:^|\s)-(?:w|windowstyle)\s+hidden\b", command)
    if encoded or hidden:
        return "PowerShell Encoded or Hidden Execution Indicator"
    return None


def detect_powershell_expression(command):
    command = str(command)
    if _has_executable(command, ("powershell", "pwsh")) and re.search(
        r"(?i)\b(?:iex|invoke-expression)\b", command
    ):
        return "PowerShell Dynamic Expression Execution"
    return None


def detect_certutil(command):
    command = str(command)
    if (
        _has_executable(command, ("certutil",))
        and re.search(r"(?i)\s-(?:urlcache|verifyctl)\b", command)
        and re.search(r"(?i)https?://", command)
    ):
        return "Certutil Remote Retrieval Indicator"
    return None


def detect_certutil_decode(command):
    command = str(command)
    if _has_executable(command, ("certutil",)) and re.search(
        r"(?i)\s-(?:decode|decodehex)\b", command
    ):
        return "Certutil File Decode Operation"
    return None


def detect_bitsadmin(command):
    command = str(command)
    if (
        _has_executable(command, ("bitsadmin",))
        and re.search(r"(?i)/(?:transfer|addfile)\b", command)
        and re.search(r"(?i)https?://", command)
    ):
        return "Bitsadmin Remote Transfer Job"
    return None


def detect_mshta(command):
    command = str(command)
    if _has_executable(command, ("mshta",)) and re.search(
        r"(?i)(?:https?://|javascript:|vbscript:)", command
    ):
        return "MSHTA Script or Remote Content Indicator"
    return None


def detect_regsvr32(command):
    command = str(command)
    if (
        _has_executable(command, ("regsvr32",))
        and re.search(r"(?i)\s/i:", command)
        and re.search(r"(?i)(?:https?://|scrobj\.dll)", command)
    ):
        return "Regsvr32 Remote Scriptlet"
    return None


def detect_rundll32(command):
    command = str(command)
    if (
        _has_executable(command, ("rundll32",))
        and re.search(r"(?i)(?:javascript:|url\.dll)", command)
        and re.search(r"(?i)https?://", command)
    ):
        return "Rundll32 Script or URL Proxy Execution"
    return None


def detect_office_child(command, parent_process):
    office_parent = _has_executable(
        parent_process, ("winword", "excel", "powerpnt", "outlook")
    )
    interpreter_child = _has_executable(
        command, ("cmd", "powershell", "pwsh", "wscript", "cscript", "mshta")
    )
    if office_parent and interpreter_child:
        return "Office Application Spawned a Script Interpreter"
    return None


def _writable_path(path):
    return bool(
        re.search(
            r"(?i)(?:\\users\\public\\|\\users\\[^\\]+\\appdata\\|\\windows\\temp\\|\\programdata\\|\\temp\\)",
            str(path),
        )
    )


def detect_service_path(event):
    if _event_id(event) != "7045":
        return None
    image_path = _event_value(event, "image_path", "ImagePath")
    if _writable_path(image_path):
        return "Service Binary Uses a User-Writable Path"
    return None


def detect_wmi_consumer(event):
    if _event_id(event) != "20":
        return None
    destination = _event_value(event, "destination", "Destination")
    flagged_destination = re.search(
        r"(?i)(?:powershell|cmd\.exe|wscript|cscript|mshta|\\users\\|\\programdata\\|\\temp\\)",
        destination,
    )
    if flagged_destination:
        return "WMI Event Consumer References an Interpreter or Writable Path"
    return None


RULES = [
    ("PS-001", detect_powershell, "High", "T1059.001",
     "Encoded-command and hidden-window flags warrant review, but approved automation may use them."),
    ("PS-002", detect_powershell_expression, "Medium", "T1059.001",
     "Dynamic expression calls need script and parent-process review; the pattern alone is not proof of abuse."),
    ("CMD-001", None, "High", "T1059",
     "Office-to-interpreter process lineage warrants review; approved macros and add-ins are benign explanations."),
    ("CERT-001", detect_certutil, "Medium", "T1105",
     "Remote retrieval with Certutil should be checked against approved PKI and software-distribution activity."),
    ("CERT-002", detect_certutil_decode, "Medium", "T1140",
     "Certutil decoding can be legitimate; inspect the source, output path, and subsequent execution."),
    ("BITS-001", detect_bitsadmin, "Medium", "T1197",
     "A transfer command does not prove a BITS job completed; correlate with BITS client logs."),
    ("MSHTA-001", detect_mshta, "High", "T1218.005",
     "Inline script or remote HTA use warrants review; approved legacy HTA applications may be benign."),
    ("REG-001", detect_regsvr32, "High", "T1218.010",
     "Remote scriptlet loading warrants review; confirm the target, parent process, signer, and change context."),
    ("RUNDLL-001", detect_rundll32, "Medium", "T1218.011",
     "Script or URL proxy indicators need module and process-tree review; Rundll32 also has legitimate uses."),
    ("SVC-001", None, "Medium", "T1543.003",
     "A service binary in a writable location may be persistence; verify the installer and service owner."),
    ("WMI-001", None, "Medium", "T1546.003",
     "Correlate consumer creation with filter and binding events; a consumer event alone does not prove an active subscription."),
]


def analyze_command(command, parent_process="", event=None):
    detections = []

    for rule_id, rule, severity, technique, explanation in RULES:
        if rule_id == "CMD-001":
            result = detect_office_child(command, parent_process)
        elif rule_id == "SVC-001":
            result = detect_service_path(event)
        elif rule_id == "WMI-001":
            result = detect_wmi_consumer(event)
        else:
            result = rule(command)

        if result is not None:
            detections.append({
                "rule_id": rule_id,
                "detection": result,
                "severity": severity,
                "mitre_technique": technique,
                "explanation": explanation,
            })

    if event is not None and _event_id(event) == "4104":
        script = _event_value(event, "scriptblocktext", "ScriptBlockText")
        if re.search(
            r"(?i)(?:frombase64string|invoke-expression|\biex\b|downloadstring)",
            script,
        ):
            detections.append({
                "rule_id": "PS-003",
                "detection": "PowerShell Script Block Contains High-Risk Execution Indicators",
                "severity": "Medium",
                "mitre_technique": "T1059.001",
                "explanation": "Review the complete script block and its context; administrative scripts may use these methods.",
            })

    return detections
