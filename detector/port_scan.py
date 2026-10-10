from __future__ import annotations

from collections import defaultdict
from datetime import datetime

from detector.recommendations import get_recommendation
from detector.severity import make_alert, severity_from_threshold


def _parse_ts(timestamp):
    if timestamp is None:
        return None
    if isinstance(timestamp, datetime):
        return timestamp
    try:
        return datetime.strptime(str(timestamp), "%Y-%m-%d %H:%M:%S")
    except ValueError:
        try:
            return datetime.fromisoformat(str(timestamp))
        except ValueError:
            return None


def detect_port_scan(events, medium_threshold: int = 10, high_threshold: int = 20, time_window_seconds: int = 10):
    if not events:
        return []

    grouped: dict[tuple[str, str], list[tuple[datetime, dict]]] = defaultdict(list)
    for event in events:
        src = str(event.get("source_ip") or "unknown").strip()
        dst = str(event.get("destination_ip") or "unknown").strip()
        if src == "unknown" or dst == "unknown":
            continue
        ts = _parse_ts(event.get("timestamp"))
        if ts is None:
            continue
        grouped[(src, dst)].append((ts, event))

    alerts = []
    seen_windows: set[tuple[str, str, str, int]] = set()
    for (src, dst), items in grouped.items():
        items.sort(key=lambda item: item[0])
        for start_index, (start_time, _) in enumerate(items):
            window_items = [
                (ts, event)
                for ts, event in items[start_index:]
                if (ts - start_time).total_seconds() <= time_window_seconds
            ]
            distinct_ports = {
                int(event.get("destination_port"))
                for _, event in window_items
                if event.get("destination_port") is not None
            }
            if len(distinct_ports) < medium_threshold:
                continue

            port_count = len(distinct_ports)
            severity = severity_from_threshold(port_count, medium_threshold, high_threshold)
            window_label = start_time.strftime("%Y-%m-%d %H:%M:%S")
            dedupe_key = (src, dst, window_label, port_count)
            if dedupe_key in seen_windows:
                continue
            seen_windows.add(dedupe_key)

            tcp_indicators = sum(1 for _, event in window_items if str(event.get("protocol") or "").upper() == "TCP")
            evidence = (
                f"Source {src} contacted {len(distinct_ports)} distinct destination ports for {dst} "
                f"within {time_window_seconds} seconds; TCP indicator count: {tcp_indicators}."
            )
            alert = make_alert(
                detection_type="port_scan",
                source_ip=src,
                destination_ip=dst,
                description=f"Possible port scan activity detected from {src} to {dst}.",
                evidence=evidence,
                recommended_action=get_recommendation("port_scan"),
                severity=severity,
                timestamp=start_time.strftime("%Y-%m-%d %H:%M:%S"),
            )
            alerts.append(alert.to_dict())
    return alerts
