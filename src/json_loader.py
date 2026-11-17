
import json

import pandas as pd

from src.normalizer import normalize_logs
from src.loader import validate_logs



def load_json(file_path):
    try:
        if hasattr(file_path, "read"):
            data = json.load(file_path)
        else:
            with open(
                file_path,
                "r",
                encoding="utf-8"
            ) as file:
                data = json.load(file)

    except FileNotFoundError as error:
        raise ValueError(
            "The JSON file was not found."
        ) from error

    except (
        json.JSONDecodeError,
        UnicodeDecodeError
    ) as error:
        raise ValueError(
            "Invalid JSON file."
        ) from error

    if isinstance(data, dict):
        if "events" in data:
            data = data["events"]
        else:
            data = [data]

    if not isinstance(data, list):
        raise ValueError(
            "JSON must contain a list of events."
        )

    if not all(isinstance(item, dict) for item in data):
        raise ValueError(
            "Each JSON event must be an object."
        )

    df = pd.DataFrame(data)

    df = normalize_logs(df)

    return validate_logs(df)

