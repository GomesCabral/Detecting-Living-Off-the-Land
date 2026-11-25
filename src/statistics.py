
def calculate_statistics(logs, alerts):
    total_events = len(logs)
    total_alerts = len(alerts)

    alerted_events = len({
        alert["event_id"]
        for alert in alerts
    })

    affected_computers = len({
        str(alert["computer"])
        for alert in alerts
        if str(alert["computer"]).strip().lower()
        not in ("", "unknown", "nan", "none", "<na>")
    })

    detection_rate = (
        alerted_events / total_events * 100
        if total_events > 0
        else 0.0
    )

    return {
        "total_events": total_events,
        "total_alerts": total_alerts,
        "alerted_events": alerted_events,
        "affected_computers": affected_computers,
        "detection_rate": round(detection_rate, 2)
    }
