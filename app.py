from __future__ import annotations

import csv
import io
import json
from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st

from detector.anomaly import detect_anomalies
from detector.brute_force import detect_brute_force
from detector.pcap_analyzer import analyze_pcap_file
from detector.port_scan import detect_port_scan
from detector.vpn_analyzer import detect_vpn_anomalies
from utils.data_generator import generate_sample_data
from utils.file_handler import export_alerts_csv, export_alerts_json, unique_report_path, validate_upload

PROJECT_ROOT = Path(__file__).resolve().parent
DATA_DIR = PROJECT_ROOT / "data"


def ensure_demo_data() -> dict[str, Path]:
    if not (DATA_DIR / "sample_auth_logs.csv").exists() or not (DATA_DIR / "sample_vpn_logs.csv").exists():
        return generate_sample_data(PROJECT_ROOT)
    return {
        "auth": DATA_DIR / "sample_auth_logs.csv",
        "vpn": DATA_DIR / "sample_vpn_logs.csv",
        "pcap": DATA_DIR / "sample_capture.pcap",
    }


def load_csv_records(path: Path) -> list[dict]:
    if not path.exists():
        return []
    df = pd.read_csv(path, dtype=str, on_bad_lines="skip")
    return df.to_dict(orient="records")


def normalize_alerts(alerts):
    normalized = []
    for alert in alerts:
        if isinstance(alert, dict):
            normalized.append(alert)
    return normalized


def build_summary_metrics(alerts: list[dict], pcap_summary: dict | None = None) -> dict:
    total_alerts = len(alerts)
    high_alerts = sum(1 for alert in alerts if str(alert.get("severity", "")).upper() == "HIGH")
    medium_alerts = sum(1 for alert in alerts if str(alert.get("severity", "")).upper() == "MEDIUM")
    packets = int((pcap_summary or {}).get("total_packets", 0))
    unique_ips = int((pcap_summary or {}).get("unique_source_ips", 0)) + int((pcap_summary or {}).get("unique_destination_ips", 0))
    return {
        "packets_processed": packets,
        "unique_ips": unique_ips,
        "total_alerts": total_alerts,
        "high_alerts": high_alerts,
        "medium_alerts": medium_alerts,
    }


st.set_page_config(page_title="NetGuard | NIDS Dashboard", layout="wide")
st.markdown(
    """
    <style>
    .stApp { background-color: #0f172a; color: #e2e8f0; }
    div[data-testid=stSidebar] { background-color: #111827; }
    .block-container { padding-top: 1rem; }
    </style>
    """,
    unsafe_allow_html=True,
)

st.sidebar.title("NetGuard")
st.sidebar.caption("Synthetic security assessment dashboard")
page = st.sidebar.radio("Navigation", ["Overview", "PCAP Traffic Analysis", "Port Scan Detection", "Brute-Force Detection", "VPN Security Assessment", "Alerts and Activity Logs", "Reports and Export"])

if "alerts" not in st.session_state:
    st.session_state.alerts = []
if "pcap_summary" not in st.session_state:
    st.session_state.pcap_summary = {}
if "pcap_events" not in st.session_state:
    st.session_state.pcap_events = []
if "demo_mode" not in st.session_state:
    st.session_state.demo_mode = False


if page == "Overview":
    st.title("NetGuard: Network Intrusion Detection System")
    st.caption("Synthetic demo environment for authorized network traffic and VPN security assessment.")
    st.info("This dashboard analyzes local data only. It does not inspect encrypted VPN payloads or claim real-time malicious intent.")

    col_a, col_b = st.columns([1, 1])
    with col_a:
        if st.button("Generate demo dataset"):
            ensure_demo_data()
            st.success("Synthetic sample files created in the data folder.")
    with col_b:
        if st.button("Run demo analysis"):
            st.session_state.demo_mode = True
            demo_files = ensure_demo_data()
            pcap_summary, events = analyze_pcap_file(demo_files["pcap"])
            auth_rows = load_csv_records(demo_files["auth"])
            vpn_rows = load_csv_records(demo_files["vpn"])

            alerts = []
            alerts.extend(detect_port_scan(events, medium_threshold=10, high_threshold=20, time_window_seconds=10))
            alerts.extend(detect_brute_force(auth_rows, time_window_seconds=300, medium_threshold=5, high_threshold=10))
            alerts.extend(detect_anomalies(events, packet_threshold=80, volume_multiplier=2.5, repeated_attempts=4, time_window_seconds=60))
            alerts.extend(detect_vpn_anomalies(vpn_rows, auth_failure_threshold=3, repeated_disconnect_threshold=3, time_window_seconds=600))
            st.session_state.pcap_summary = pcap_summary
            st.session_state.pcap_events = events
            st.session_state.alerts = normalize_alerts(alerts)
            st.success("Demo analysis completed successfully.")

    metrics = build_summary_metrics(st.session_state.alerts, st.session_state.pcap_summary)
    cols = st.columns(5)
    labels = ["Packets processed", "Unique IPs", "Total alerts", "High alerts", "Medium alerts"]
    values = [metrics["packets_processed"], metrics["unique_ips"], metrics["total_alerts"], metrics["high_alerts"], metrics["medium_alerts"]]
    for col, label, value in zip(cols, labels, values):
        col.metric(label, value)

    if st.session_state.pcap_summary:
        if st.session_state.pcap_summary.get("protocol_distribution"):
            df = pd.DataFrame(list(st.session_state.pcap_summary["protocol_distribution"].items()), columns=["Protocol", "Packets"])
            fig = px.pie(df, names="Protocol", values="Packets", title="Protocol Distribution")
            st.plotly_chart(fig, use_container_width=True)

    if st.session_state.alerts:
        alert_df = pd.DataFrame(st.session_state.alerts)
        severity_counts = alert_df["severity"].value_counts().reset_index()
        severity_counts.columns = ["Severity", "Count"]
        fig = px.bar(severity_counts, x="Severity", y="Count", color="Severity", title="Alert Severity Distribution")
        st.plotly_chart(fig, use_container_width=True)

    if not st.session_state.alerts:
        st.info("No alerts available yet. Upload files or generate demo data to start analysis.")

elif page == "PCAP Traffic Analysis":
    st.title("PCAP Traffic Analysis")
    uploaded_pcap = st.file_uploader("Upload a PCAP or PCAPNG file", type=["pcap", "pcapng"])
    if uploaded_pcap is not None:
        try:
            validate_upload(uploaded_pcap.name, uploaded_pcap.size)
            file_bytes = uploaded_pcap.getvalue()
            temp_path = PROJECT_ROOT / "data" / uploaded_pcap.name
            temp_path.parent.mkdir(parents=True, exist_ok=True)
            temp_path.write_bytes(file_bytes)
            summary, events = analyze_pcap_file(temp_path)
            st.session_state.pcap_summary = summary
            st.session_state.pcap_events = events
            st.success(f"Processed {summary['total_packets']} packets from {uploaded_pcap.name}.")
        except Exception as exc:  # pragma: no cover
            st.error(str(exc))

    if st.session_state.pcap_summary:
        summary = st.session_state.pcap_summary
        st.subheader("Summary")
        st.json({
            "total_packets": summary.get("total_packets", 0),
            "unique_source_ips": summary.get("unique_source_ips", 0),
            "unique_destination_ips": summary.get("unique_destination_ips", 0),
            "protocol_distribution": summary.get("protocol_distribution", {}),
        })
        event_df = pd.DataFrame(st.session_state.pcap_events)
        if not event_df.empty:
            st.dataframe(event_df, use_container_width=True)
    else:
        st.info("Upload a PCAP file or run the demo analysis to display packet statistics.")

elif page == "Port Scan Detection":
    st.title("Port Scan Detection")
    st.subheader("Thresholds")
    med = st.slider("Medium threshold", min_value=2, max_value=50, value=10)
    high = st.slider("High threshold", min_value=4, max_value=60, value=20)
    window = st.slider("Time window (seconds)", min_value=5, max_value=60, value=10)
    if st.button("Analyze port scan indicators"):
        if not st.session_state.pcap_events:
            demo_files = ensure_demo_data()
            summary, events = analyze_pcap_file(demo_files["pcap"])
            st.session_state.pcap_events = events
        scans = detect_port_scan(st.session_state.pcap_events, medium_threshold=med, high_threshold=high, time_window_seconds=window)
        st.session_state.alerts = normalize_alerts(st.session_state.alerts + scans)
        st.success(f"Detected {len(scans)} port-scan-related alerts.")
    if any(alert.get("detection_type") == "port_scan" for alert in st.session_state.alerts):
        port_rows = [alert for alert in st.session_state.alerts if alert.get("detection_type") == "port_scan"]
        st.dataframe(pd.DataFrame(port_rows), use_container_width=True)
    else:
        st.info("No port-scan indicators were detected in the current sample.")

elif page == "Brute-Force Detection":
    st.title("Brute-Force Detection")
    auth_file = st.file_uploader("Upload authentication log CSV", type=["csv"])
    if auth_file is not None:
        try:
            file_bytes = auth_file.getvalue()
            temp_path = PROJECT_ROOT / "data" / auth_file.name
            temp_path.write_bytes(file_bytes)
            rows = load_csv_records(temp_path)
            alerts = detect_brute_force(rows)
            st.session_state.alerts = normalize_alerts(st.session_state.alerts + alerts)
            st.success(f"Generated {len(alerts)} brute-force alerts.")
        except Exception as exc:
            st.error(str(exc))
    else:
        demo_files = ensure_demo_data()
        rows = load_csv_records(demo_files["auth"])
        if st.button("Run demo brute-force analysis"):
            alerts = detect_brute_force(rows)
            st.session_state.alerts = normalize_alerts(st.session_state.alerts + alerts)
            st.success(f"Generated {len(alerts)} brute-force alerts from sample data.")
    if any(alert.get("detection_type") == "brute_force" for alert in st.session_state.alerts):
        brute_rows = [alert for alert in st.session_state.alerts if alert.get("detection_type") == "brute_force"]
        st.dataframe(pd.DataFrame(brute_rows), use_container_width=True)

elif page == "VPN Security Assessment":
    st.title("VPN Security Assessment")
    vpn_file = st.file_uploader("Upload VPN log CSV", type=["csv"])
    if vpn_file is not None:
        try:
            temp_path = PROJECT_ROOT / "data" / vpn_file.name
            temp_path.write_bytes(vpn_file.getvalue())
            rows = load_csv_records(temp_path)
            alerts = detect_vpn_anomalies(rows)
            st.session_state.alerts = normalize_alerts(st.session_state.alerts + alerts)
            st.success(f"Generated {len(alerts)} VPN security alerts.")
        except Exception as exc:
            st.error(str(exc))
    else:
        demo_files = ensure_demo_data()
        rows = load_csv_records(demo_files["vpn"])
        if st.button("Run demo VPN assessment"):
            alerts = detect_vpn_anomalies(rows)
            st.session_state.alerts = normalize_alerts(st.session_state.alerts + alerts)
            st.success(f"Generated {len(alerts)} VPN alerts from sample data.")
    if any(alert.get("detection_type", "").startswith("vpn_") for alert in st.session_state.alerts):
        vpn_rows = [alert for alert in st.session_state.alerts if alert.get("detection_type", "").startswith("vpn_")]
        st.dataframe(pd.DataFrame(vpn_rows), use_container_width=True)

elif page == "Alerts and Activity Logs":
    st.title("Alerts and Activity Logs")
    if st.session_state.alerts:
        df = pd.DataFrame(st.session_state.alerts)
        severity_filter = st.selectbox("Severity filter", ["All", "LOW", "MEDIUM", "HIGH"])
        source_filter = st.selectbox("Source IP filter", ["All"] + sorted({alert.get("source_ip", "") for alert in st.session_state.alerts if alert.get("source_ip")}))
        detection_filter = st.selectbox("Detection type", ["All"] + sorted({alert.get("detection_type", "") for alert in st.session_state.alerts if alert.get("detection_type")}))
        filtered = df.copy()
        if severity_filter != "All":
            filtered = filtered[filtered["severity"] == severity_filter]
        if source_filter != "All":
            filtered = filtered[filtered["source_ip"] == source_filter]
        if detection_filter != "All":
            filtered = filtered[filtered["detection_type"] == detection_filter]
        st.dataframe(filtered, use_container_width=True)
        if not filtered.empty:
            selected = st.selectbox("Alert detail", ["Select one"] + filtered["alert_id"].tolist())
            if selected != "Select one":
                selected_alert = filtered[filtered["alert_id"] == selected].iloc[0]
                st.markdown(f"### {selected_alert['detection_type']}")
                st.write(selected_alert.to_dict())
    else:
        st.info("No alerts have been generated. Upload data or run the demo analysis to populate the log table.")

elif page == "Reports and Export":
    st.title("Reports and Export")
    if st.session_state.alerts:
        csv_buffer = io.StringIO()
        csv_writer = csv.DictWriter(csv_buffer, fieldnames=["alert_id", "detection_type", "timestamp", "source_ip", "destination_ip", "severity", "description", "evidence", "recommended_action"])
        csv_writer.writeheader()
        for alert in st.session_state.alerts:
            csv_writer.writerow(alert)
        csv_text = csv_buffer.getvalue()
        json_payload = json.dumps(st.session_state.alerts, indent=2)
        st.download_button("Download CSV", csv_text, file_name="netguard_alerts.csv", mime="text/csv")
        st.download_button("Download JSON", json_payload, file_name="netguard_report.json", mime="application/json")
        report_path = unique_report_path(PROJECT_ROOT / "reports", "netguard_report", ".json")
        report_path.write_text(json_payload, encoding="utf-8")
        st.success(f"Saved report to {report_path.name}.")
    else:
        st.info("No alerts are available to export yet.")

if __name__ == "__main__":
    st.warning("This application is intended for local educational use with synthetic or authorized data only.")
