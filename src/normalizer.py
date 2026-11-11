import pandas as pd

COLUMN_MAPPING = {
    "TimeCreated": "timestamp",
    "event_time": "timestamp",
    "ComputerName": "computer",
    "hostname": "computer",
    "UserName": "user",
    "username": "user",
    "CommandLine": "command_line",
    "process_command_line": "command_line"
}


def normalize_logs(df):
    df = df.copy()

    df.columns = df.columns.str.strip()

    df = df.rename(columns = COLUMN_MAPPING)

    return df