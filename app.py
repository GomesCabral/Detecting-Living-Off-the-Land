
import pandas as pd
import streamlit as st

from src.json_loader import load_json
from src.loader import load_csv
from src.analysis_engine import analyze_logs
from src.filters import filter_alerts
from src.exporter import export_alerts_csv

st.set_page_config(
    page_title="Threat Hunting Dashboard",
    page_icon="🛡️",
    layout="wide"
)

st.title("Threat Hunting Dashboard")

st.write(
    "Analyze suspicious Windows activity using "
    "JSON and Sigma detection rules."
)

mode = st.selectbox(
    "Detection Engine",
    ["Both", "JSON", "Sigma"]
)

uploaded_file = st.file_uploader(
    "Upload Windows Logs",
    type=["csv", "json"]
)

if uploaded_file is not None:
    try:
        file_extension = uploaded_file.name.lower().split(".")[-1]

        if file_extension == "csv":
            logs = load_csv(uploaded_file)

        elif file_extension == "json":
            logs = load_json(uploaded_file)

        else:
            raise ValueError(
                "Unsupported file format."
            )

        st.success("File loaded successfully!")

        st.subheader("Windows Events")

        st.dataframe(
            logs,
            use_container_width=True
        )

        alerts = analyze_logs(logs, mode=mode)

        total_events = len(logs)
        total_alerts = len(alerts)

        alerted_events = len({
            alert["event_id"]
            for alert in alerts
        })

        affected_computers = len({
            str(alert["computer"])
            for alert in alerts
            if pd.notna(alert["computer"])
        })

        col1, col2, col3, col4 = st.columns(4)

        with col1:
            st.metric("Total Events", total_events)

        with col2:
            st.metric("Total Alerts", total_alerts)

        with col3:
            st.metric("Events With Alerts", alerted_events)

        with col4:
            st.metric("Affected Computers", affected_computers)

        st.subheader("Detection Results")

        if alerts:
            alerts_df = pd.DataFrame(alerts)

            st.warning(
                f"{total_alerts} detections found!"
            )

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
                f"Showing {len(filtered_df)} of "
                f"{total_alerts} alerts."
            )

            st.dataframe(
                filtered_df,
                use_container_width=True
            )

            st.download_button(
                label="Download Filtered Alerts CSV",
                data=export_alerts_csv(filtered_df),
                file_name="threat_hunting_alerts.csv",
                mime="text/csv"
            )

        else:
            st.info(
                "No matching detection rules found."
            )

    except (ValueError, OSError) as error:
        st.error(f"Analysis error: {error}")