
import pandas as pd


COLUMN_MAPPING = {
    "timecreated": "timestamp",
    "event_time": "timestamp",
    "timestamp": "timestamp",
    "utc_time": "timestamp",

    "computername": "computer",
    "hostname": "computer",
    "host": "computer",
    "computer": "computer",

    "username": "user",
    "user": "user",
    "accountname": "user",

    "commandline": "command_line",
    "process_command_line": "command_line",
    "command_line": "command_line",

    "image": "Image",
    "process_path": "Image",
    "process_image": "Image"
}


def normalize_logs(df):
    df = df.copy()

    df.columns = [
        str(column).strip()
        for column in df.columns
    ]

    renamed_columns = {}

    for column in df.columns:
        normalized_name = column.lower()

        if normalized_name in COLUMN_MAPPING:
            renamed_columns[column] = (
                COLUMN_MAPPING[normalized_name]
            )

    df = df.rename(columns=renamed_columns)

    if df.columns.duplicated().any():
        duplicates = df.columns[
            df.columns.duplicated()
        ].tolist()

        raise ValueError(
            f"Duplicate columns after normalization: {duplicates}"
        )

    for column in ["timestamp", "computer", "user"]:
        if column in df.columns:
            df[column] = (
                df[column]
                .fillna("Unknown")
                .astype(str)
                .str.strip()
                .replace("", "Unknown")
            )

    if "command_line" in df.columns:
        df["command_line"] = (
            df["command_line"]
            .fillna("")
            .astype(str)
            .str.strip()
        )

    if "Image" in df.columns:
        df["Image"] = (
            df["Image"]
            .fillna("")
            .astype(str)
            .str.strip()
        )

    return df
