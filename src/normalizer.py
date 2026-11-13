import pandas as pd

COLUMN_MAPPING = {
    "TimeCreated": "timestamp",
    "event_time": "timestamp",
    "ComputerName": "computer",
    "hostname": "computer",
    "UserName": "user",
    "username": "user",
    "CommandLine": "command_line",
    "process_command_line": "command_line",
    # Hafi Week 2: retain process lineage and event data for contextual rules.
    "ParentImage": "parent_process",
    "ParentProcessName": "parent_process",
    "parent_process_name": "parent_process",
    "EventID": "event_id",
    "EventCode": "event_id",
    "ImagePath": "image_path",
    "Destination": "destination",
    "ScriptBlockText": "scriptblocktext"
}


def normalize_logs(df):
    df = df.copy()

    df.columns = df.columns.str.strip()

    df = df.rename(columns = COLUMN_MAPPING)

    return df