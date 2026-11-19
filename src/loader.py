import pandas as pd

from pathlib import Path
from src.normalizer import normalize_logs


REQUIRED_COLUMNS = [
    "timestamp",
    "computer",
    "user",
    "command_line"
]


def validate_file(uploaded_file):

    if uploaded_file is None:
        raise ValueError("No file uploaded.")

    extension = Path(
        uploaded_file.name
    ).suffix.lower().lstrip(".")

    allowed_extensions = ["csv", "json"]

    if extension not in allowed_extensions:
        raise ValueError(
            f"Unsupported file format: {extension}"
        )

    if uploaded_file.size == 0:
        raise ValueError("The uploaded file is empty.")

    return extension


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

    if df["command_line"].fillna("").astype(str).str.strip().eq("").all():
        raise ValueError(
            "All command_line values are empty."
        )

    return df


def load_csv(file_path):

    if hasattr(file_path, "seek"):
        file_path.seek(0)

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


def load_json(uploaded_file):

    try:

        if hasattr(uploaded_file, "seek"):
            uploaded_file.seek(0)

        df = pd.read_json(uploaded_file)

    except (ValueError, UnicodeDecodeError) as error:
        raise ValueError(
            "The JSON file could not be read correctly."
        ) from error

    df = normalize_logs(df)

    return validate_logs(df)
