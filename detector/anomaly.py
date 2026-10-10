from __future__ import annotations

from collections import defaultdict
from datetime import datetime

from detector.recommendations import get_recommendation
from detector.severity import make_alert, severity_from_threshold


def _coerce_timestamp(value):
    if value is None:
        return None
    if isinstance(value, datetime):
        return value
    for pattern in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(str(value), pattern)
        except ValueError:
            continue
    try:
        return datetime.fromisoformat(str(value))
    except ValueError:
        return None


def detect_anomalies(events, packet_threshold: int = 100, volume_multiplier: float = 2.5, repeated_attempts: int = 5, time_window_seconds: int = 60):
    if not events:
        return []

    alerts = []
    by_source: dict[str, list[datetime]] = defaultdict(list)
    by_pair: dict[tuple[str, str], list[datetime]] = defaultdict(list)

    for event in events:
        source_ip = str(event.get("source_ip") or "").strip()
        destination_ip = str(event.get("destination_ip") or "").strip()
        ts = _coerce_timestamp(event.get("timestamp"))
        if not source_ip or ts is None:
            continue
        by_source[source_ip].append(ts)
        if destination_ip and destination_ip != "unknown":
            by_pair[(source_ip, destination_ip)].append(ts)

    for source_ip, timestamps in by_source.items():
        timestamps.sort()
        for idx, ts in enumerate(timestamps):
            window = [t for t in timestamps[idx:] if (t - ts).total_seconds() <= time_window_seconds]
            if len(window) >= packet_threshold:
                severity = severity_from_threshold(len(window), packet_threshold, packet_threshold * 2)
                evidence = f"{len(window)} packets from {source_ip} within {time_window_seconds} seconds exceeds the configured threshold."
                alerts.append(
                    make_alert(
                        detection_type="anomaly",
                        source_ip=source_ip,
                        destination_ip=None,
                        description=f"Unusually high packet volume from {source_ip} indicates possible abnormal network activity.",
                        evidence=evidence,
                        recommended_action=get_recommendation("anomaly"),
                        severity=severity,
                        timestamp=ts.strftime("%Y-%m-%d %H:%M:%S"),
                    ).to_dict()
                )

    for (source_ip, destination_ip), timestamps in by_pair.items():
        timestamps.sort()
        for idx, ts in enumerate(timestamps):
            window = [t for t in timestamps[idx:] if (t - ts).total_seconds() <= time_window_seconds]
            if len(window) >= repeated_attempts:
                severity = severity_from_threshold(len(window), repeated_attempts, repeated_attempts + 5)
                alerts.append(
                    make_alert(
                        detection_type="anomaly",
                        source_ip=source_ip,
                        destination_ip=destination_ip,
                        description=f"Repeated connection attempts from {source_ip} to {destination_ip} suggest a burst of suspicious activity.",
                        evidence=f"{len(window)} attempted connections to {destination_ip} within {time_window_seconds} seconds.",
                        recommended_action=get_recommendation("anomaly"),
                        severity=severity,
                        timestamp=ts.strftime("%Y-%m-%d %H:%M:%S"),
                    ).to_dict()
                )

    # Volume spike check using average packet rate across the capture.
    if len(events) > 0:
        total_events = len(events)
        avg_packets_per_minute = total_events / max(1, (len(events) / max(1, total_events)))
        if total_events > 0 and avg_packets_per_minute * volume_multiplier < total_events:
            alerts.append(
                make_alert(
                    detection_type="anomaly",
                    source_ip="network",
                    destination_ip=None,
                    description="Traffic volume is unusually elevated compared to the baseline for the sample capture.",
                    evidence=f"Total packet count {total_events} exceeds the expected baseline by a factor of {volume_multiplier}.",
                    recommended_action=get_recommendation("anomaly"),
                    severity="MEDIUM" if total_events > 20 else "LOW",
                    timestamp=datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
                ).to_dict()
            )

    unique_alerts = []
    seen = set()
    for alert in alerts:
        key = (alert["source_ip"], alert["destination_ip"], alert["description"], alert["timestamp"])
        if key in seen:
            continue
        seen.add(key)
        unique_alerts.append(alert)
    return unique_alerts
