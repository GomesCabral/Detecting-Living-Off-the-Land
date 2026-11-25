
import pandas as pd
import streamlit as st

from src.loader import load_csv
from src.json_loader import load_json
from src.file_validator import validate_file
from src.analysis_engine import analyze_logs
from src.filters import filter_alerts
from src.exporter import export_alerts_csv

from src.statistics import calculate_statistics

from src.visualizations import (
    create_severity_chart,
    create_mitre_chart,
    create_computer_chart
)


st.set_page_config(
    page_title="Threat Hunting Dashboard",
    page_icon="🛡️",
    layout="wide"
)


# Header

st.title("🛡️ Threat Hunting Dashboard")

st.caption(
    "Windows Security | Living Off the Land | "
    "JSON & Sigma Detection"
)

st.divider()


# Sidebar

with st.sidebar:

    st.header("Analysis Configuration")

    mode = st.selectbox(
        "Detection Engine",
        ["Both", "JSON", "Sigma"]
    )

    uploaded_file = st.file_uploader(
        "Upload Windows Logs",
        type=["csv", "json"]
    )

    st.caption("Maximum file size: 10 MB")

    st.divider()

    st.subheader("About")

    st.write(
        "A threat hunting tool for identifying "
        "suspicious Windows command-line activity."
    )

    st.caption(
        "Alerts indicate suspicious behavior, "
        "not confirmed attacks."
    )


# Initial screen

if uploaded_file is None:

    st.info(
        "Upload a CSV or JSON file "
        "to start the analysis."
    )

    st.subheader("Supported Fields")

    st.code(
        "timestamp\n"
        "computer\n"
        "user\n"
        "command_line\n"
        "Image (required by some Sigma rules)",
        language="text"
    )

    st.stop()


# File validation and loading

try:

    extension = validate_file(uploaded_file)

    if extension == ".csv":
        logs = load_csv(uploaded_file)

    elif extension == ".json":
        logs = load_json(uploaded_file)

    else:
        raise ValueError("Unsupported file format.")

    st.success(
        f"Successfully loaded {uploaded_file.name}"
    )

    if mode in ("Sigma", "Both"):

        if "Image" not in logs.columns:

            st.warning(
                "The Image column is missing. "
                "Sigma rules requiring this field "
                "cannot be fully evaluated."
            )

        elif logs["Image"].eq("").any():

            missing_images = int(
                logs["Image"].eq("").sum()
            )

            st.warning(
                f"{missing_images} events have no Image. "
                "Some Sigma detections may be unavailable."
            )

    missing_commands = int(
        logs["command_line"].eq("").sum()
    )

    if missing_commands:

        st.warning(
            f"{missing_commands} events have "
            "missing command lines."
        )


    # Detection

    with st.spinner("Analyzing Windows events..."):

        alerts = analyze_logs(logs, mode=mode)

    stats = calculate_statistics(logs, alerts)


    # Metrics

    st.subheader("Analysis Overview")

    col1, col2, col3, col4 = st.columns(4)

    col1.metric(
        "Total Events",
        stats["total_events"]
    )

    col2.metric(
        "Total Alerts",
        stats["total_alerts"]
    )

    col3.metric(
        "Detection Rate",
        f"{stats['detection_rate']}%"
    )

    col4.metric(
        "Affected Computers",
        stats["affected_computers"]
    )

    st.caption(
        f"Events with alerts: {stats['alerted_events']}"
    )


    # Navigation tabs

    overview_tab, alerts_tab, events_tab = st.tabs([
        "Overview",
        "Detection Results",
        "Raw Events"
    ])


    # Overview

    with overview_tab:

        if alerts:

            alerts_df = pd.DataFrame(alerts)

            chart1, chart2 = st.columns(2)

            with chart1:

                st.plotly_chart(
                    create_severity_chart(alerts_df),
                    use_container_width=True
                )

            with chart2:

                st.plotly_chart(
                    create_mitre_chart(alerts_df),
                    use_container_width=True
                )

            st.plotly_chart(
                create_computer_chart(alerts_df),
                use_container_width=True
            )

        else:

            st.info(
                "No matching detection rules found."
            )


    # Detection Results

    with alerts_tab:

        if not alerts:

            st.info("No alerts to display.")

        else:

            alerts_df = pd.DataFrame(alerts)

            st.subheader("Filter Alerts")

            col1, col2, col3 = st.columns(3)

            with col1:

                severity = st.selectbox(
                    "Severity",
                    ["All"] + sorted(
                        alerts_df["severity"]
                        .dropna()
                        .unique()
                        .tolist()
                    )
                )

            with col2:

                computer = st.selectbox(
                    "Computer",
                    ["All"] + sorted(
                        alerts_df["computer"]
                        .dropna()
                        .astype(str)
                        .unique()
                        .tolist()
                    )
                )

            with col3:

                technique = st.selectbox(
                    "MITRE ATT&CK",
                    ["All"] + sorted(
                        alerts_df["mitre_technique"]
                        .dropna()
                        .unique()
                        .tolist()
                    )
                )

            filtered_df = filter_alerts(
                alerts_df,
                severity=severity,
                computer=computer,
                technique=technique
            )

            st.write(
                f"Showing {len(filtered_df)} "
                f"of {len(alerts_df)} alerts."
            )

            st.dataframe(
                filtered_df,
                use_container_width=True,
                hide_index=True
            )

            st.download_button(
                label="Download Filtered Alerts CSV",
                data=export_alerts_csv(filtered_df),
                file_name="threat_hunting_alerts.csv",
                mime="text/csv"
            )


            # Alert Investigation

            if not filtered_df.empty:

                st.divider()

                st.subheader("Alert Investigation")

                selected_id = st.selectbox(
                    "Select an alert",
                    filtered_df["alert_id"].tolist()
                )

                selected_alert = filtered_df[
                    filtered_df["alert_id"] == selected_id
                ].iloc[0]

                left, right = st.columns(2)

                with left:

                    st.write(
                        "**Alert ID:**",
                        selected_alert["alert_id"]
                    )

                    st.write(
                        "**Event ID:**",
                        selected_alert["event_id"]
                    )

                    st.write(
                        "**Computer:**",
                        selected_alert["computer"]
                    )

                    st.write(
                        "**User:**",
                        selected_alert["user"]
                    )

                    st.write(
                        "**Timestamp:**",
                        selected_alert["timestamp"]
                    )

                with right:

                    st.write(
                        "**Detection:**",
                        selected_alert["detection"]
                    )

                    st.write(
                        "**Severity:**",
                        selected_alert["severity"]
                    )

                    st.write(
                        "**MITRE Technique:**",
                        selected_alert["mitre_technique"]
                    )

                    st.write(
                        "**Detection Engines:**",
                        selected_alert["engines"]
                    )

                    st.write(
                        "**Rule IDs:**",
                        selected_alert["rule_ids"]
                    )

                st.write("**Command Line:**")

                st.code(
                    str(selected_alert["command_line"]),
                    language="text"
                )


    # Raw Events

    with events_tab:

        st.subheader("Normalized Windows Events")

        st.dataframe(
            logs,
            use_container_width=True,
            hide_index=True
        )


except (ValueError, OSError) as error:

    st.error(f"Analysis error: {error}")
