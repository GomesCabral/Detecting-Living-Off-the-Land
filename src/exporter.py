import csv
import io
 
import pandas as pd
 
 
DANGEROUS_PREFIXES = ("=", "+", "-", "@")
 
 
def sanitize_csv_value(value):
    if pd.isna(value):
        return ""
 
    text = str(value)
 
    if text.lstrip().startswith(DANGEROUS_PREFIXES):
        return "'" + text
 
    return text
 
 
def export_alerts_csv(alerts_df):
    safe_df = alerts_df.copy()
 
    for column in safe_df.columns:
        safe_df[column] = safe_df[column].map(
            sanitize_csv_value
        )
 
    output = io.StringIO()
 
    safe_df.to_csv(
        output,
        index=False,
        quoting=csv.QUOTE_ALL
    )
 
    return output.getvalue().encode("utf-8-sig")

 
