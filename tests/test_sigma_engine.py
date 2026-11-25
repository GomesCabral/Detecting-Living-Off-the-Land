from src.sigma_engine import (
    load_sigma_rule,
    evaluate_sigma_rule
)


def get_rule():
    return load_sigma_rule(
        "rules/sigma/powershell_encoded.yml"
    )


def test_sigma_powershell_detection():
    event = {
        "Image": r"C:\Windows\System32\powershell.exe",
        "CommandLine": "powershell.exe -enc SQBFAFgA"
    }

    assert evaluate_sigma_rule(event, get_rule()) is True


def test_sigma_normal_process():
    event = {
        "Image": r"C:\Windows\System32\notepad.exe",
        "CommandLine": "notepad.exe"
    }

    assert evaluate_sigma_rule(event, get_rule()) is False


def test_sigma_wrong_image():
    event = {
        "Image": r"C:\Windows\System32\cmd.exe",
        "CommandLine": "echo powershell.exe -enc SQBFAFgA"
    }

    assert evaluate_sigma_rule(event, get_rule()) is False


def test_sigma_pwsh_detection():
    event = {
        "Image": r"C:\Program Files\PowerShell\7\pwsh.exe",
        "CommandLine": "pwsh.exe -encodedcommand SQBFAFgA"
    }

    assert evaluate_sigma_rule(event, get_rule()) is True
