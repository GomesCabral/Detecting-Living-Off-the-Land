import csv
import io


def export_alerts_csv(alerts_df):
    output = io.StringIO()

    alerts_df.to_csv(
        output,
        index = False,
        quoting = csv.QUOTE_ALL
    )

    return output.getvalue().encode("utf-8-sig")