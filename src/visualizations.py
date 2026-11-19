
import plotly.express as px


def create_severity_chart(alerts_df):
    severity_counts = (
        alerts_df["severity"]
        .value_counts()
        .reset_index()
    )

    severity_counts.columns = [
        "Severity",
        "Count"
    ]

    fig = px.pie(
        severity_counts,
        names="Severity",
        values="Count",
        hole=0.55,
        title="Severity Distribution",
        color="Severity",
        color_discrete_map={
            "Critical": "#991B1B",
            "High": "#EF4444",
            "Medium": "#F59E0B",
            "Low": "#22C55E",
            "Informational": "#64748B"
        }
    )

    return fig


def create_mitre_chart(alerts_df):
    technique_counts = (
        alerts_df["mitre_technique"]
        .value_counts()
        .reset_index()
    )

    technique_counts.columns = [
        "Technique",
        "Count"
    ]

    fig = px.bar(
        technique_counts,
        x="Count",
        y="Technique",
        orientation="h",
        title="MITRE ATT&CK Techniques",
        text="Count"
    )

    fig.update_layout(
        yaxis={"categoryorder": "total ascending"}
    )

    return fig


def create_computer_chart(alerts_df):
    computer_counts = (
        alerts_df["computer"]
        .value_counts()
        .reset_index()
        .head(10)
    )

    computer_counts.columns = [
        "Computer",
        "Count"
    ]

    fig = px.bar(
        computer_counts,
        x="Computer",
        y="Count",
        title="Top 10 Computers by Alert Count",
        text="Count"
    )

    return fig
