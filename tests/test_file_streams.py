import io
import json

from src.loader import load_csv
from src.json_loader import load_json


def test_repeated_csv_read():

    content = (
        "timestamp,computer,user,command_line\n"
        "2026-11-19,PC-01,Admin,whoami\n"
    )

    file = io.BytesIO(content.encode("utf-8"))

    first = load_csv(file)
    second = load_csv(file)

    assert first.equals(second)


def test_repeated_json_read():

    events = [
        {
            "timestamp": "2026-11-19",
            "computer": "PC-01",
            "user": "Admin",
            "command_line": "whoami"
        }
    ]

    file = io.BytesIO(
        json.dumps(events).encode("utf-8")
    )

    first = load_json(file)
    second = load_json(file)

    assert first.equals(second)
