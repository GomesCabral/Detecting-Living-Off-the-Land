import streamlit as st

from src.loader import load_csv
from src.detector import analyze_command


#page configuration
st.set_page_config(
    page_title="Threat Hunting Dashboard",
    page_icon="🛡️",
    layout="wide"
)

#dashboard title
st.title("Threat Hunting Dashboard")

st.write(
    "Detect suspicious Windows commands "
    "using Living Off the Land techniques."
)

#upload CSV file
uploaded_file = st.file_uploader(
    "Upload Windows Logs",
    type=["csv"]
)

#process uploaded file
if uploaded_file is not None:
    try:
        logs = load_csv(uploaded_file)

        st.success("File uploaded successfully!")

        #display Windows events
        st.subheader("Windows Events")

        st.dataframe(
            logs,
            use_container_width=True
        )

        
        # Threat detection
        st.subheader("Threat Detection")

        alerts = []
        events_with_alerts = 0

        for index, row in logs.iterrows():

            command = row["command_line"]
            detections = analyze_command(command)

            # Count events with at least one detection
            if detections:
                events_with_alerts += 1

            # Store each detection
            for detection in detections:
                alerts.append({
                    "timestamp": row["timestamp"],
                    "computer": row["computer"],
                    "user": row["user"],
                    "command_line": command,
                    "detection": detection["detection"],
                    "severity": detection["severity"],
                    "mitre_technique": detection["mitre_technique"]
                })

        # Security metrics - OUTSIDE the for loop
        st.subheader("Security Overview")

        total_events = len(logs)
        total_alerts = len(alerts)
        events_without_alerts = total_events - events_with_alerts

        col1, col2, col3 = st.columns(3)

        with col1:
            st.metric("Total Events", total_events)

        with col2:
            st.metric("Total Alerts", total_alerts)

        with col3:
            st.metric(
                "Events Without Alerts",
                events_without_alerts
            )

        # Display detection results
        if alerts:
            st.warning(
                f"{total_alerts} suspicious detections found!"
            )

            st.dataframe(
                alerts,
                use_container_width=True
            )

        else:
            st.success("No suspicious patterns detected.")


    except ValueError as error:
        st.error(f"Error loading file: {error}")
