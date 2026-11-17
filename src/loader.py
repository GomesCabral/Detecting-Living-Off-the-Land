
import pandas as pd

from src.normalizer import normalize_logs


REQUIRED_COLUMNS = [
    "timestamp",
    "computer",
    "user",
    "command_line"
]



def validate_columns(df):
    missing = [
        column
        for column in REQUIRED_COLUMNS
        if column not in df.columns
    ]

    if missing:
        raise ValueError(
            f"Missing required columns: {missing}"
        )

    return True



def validate_logs(df):
    if not isinstance(df, pd.DataFrame):
        raise ValueError("Invalid logs data structure.")

    if df.empty:
        raise ValueError("The file contains no events.")

    validate_columns(df)

    if df["command_line"].eq("").all():
        raise ValueError(
            "All command_line values are empty."
        )

    return df


def load_csv(file_path):
    try:
        df = pd.read_csv(file_path)

    except pd.errors.EmptyDataError as error:
        raise ValueError(
            "The CSV file is empty."
        ) from error

    except FileNotFoundError as error:
        raise ValueError(
            "The CSV file was not found."
        ) from error

    except (
        UnicodeDecodeError,
        pd.errors.ParserError
    ) as error:
        raise ValueError(
            "The CSV file could not be read correctly."
        ) from error

    df = normalize_logs(df)

    return validate_logs(df)
