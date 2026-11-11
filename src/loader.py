import pandas as pd

from src.normalizer import normalize_logs

REQUIRED_COLUMNS = [
    "timestamp",
    "computer",
    "user",
    "command_line"
]


def validate_columns(df):
    missing_columns = []

    for column in REQUIRED_COLUMNS:
        if column not in df.columns:
            missing_columns.append(column)

    if missing_columns:
        raise ValueError(
            f"Missing required columns: {missing_columns}"
        )

    return True


def load_csv(file_path):
    try:
        df = pd.read_csv(file_path)

    except pd.errors.EmptyDataError:
        raise ValueError("The CSV file is empty.")

    except FileNotFoundError:
        raise ValueError("The CSV file was not found.")

    except(UnicodeDecodeError, pd.errors.ParserError):
        raise ValueError("The CSV file could not be read correctly.")

    if df.empty:
        raise ValueError("The CSV contains no events.")

    df = normalize_logs(df)

    validate_columns(df)

    return df