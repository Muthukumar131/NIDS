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
    for pattern in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%m/%d/%Y %H:%M:%S"):
        try:
            return datetime.strptime(str(value), pattern)
        except ValueError:
            continue
    try:
        return datetime.fromisoformat(str(value))
    except ValueError:
        return None


def detect_brute_force(log_rows, time_window_seconds: int = 300, medium_threshold: int = 5, high_threshold: int = 10):
    if not log_rows:
        return []

    valid_rows = []
    for row in log_rows:
        if not isinstance(row, dict):
            continue
        source_ip = str(row.get("source_ip") or "").strip()
        username = str(row.get("username") or "unknown").strip()
        status = str(row.get("status") or "").strip().upper()
        ts = _coerce_timestamp(row.get("timestamp"))
        if not source_ip or ts is None:
            continue
        if status in {"SUCCESS", "OK", "SUCCESSFUL", "LOGIN_SUCCESS", "VALID"}:
            continue
        if "FAIL" not in status and status not in {"DENIED", "INVALID", "ERROR", "AUTH_FAILURE"}:
            continue
        valid_rows.append({"timestamp": ts, "source_ip": source_ip, "username": username, "status": status})

    grouped: dict[tuple[str, str], list[datetime]] = defaultdict(list)
    for row in valid_rows:
        grouped[(row["source_ip"], row["username"])].append(row["timestamp"])

    alerts = []
    seen: set[tuple[str, str, str, int]] = set()
    for (source_ip, username), times in grouped.items():
        times.sort()
        for idx, ts in enumerate(times):
            window = [t for t in times[idx:] if (t - ts).total_seconds() <= time_window_seconds]
            fail_count = len(window)
            if fail_count < medium_threshold:
                continue
            severity = severity_from_threshold(fail_count, medium_threshold, high_threshold)
            evidence = (
                f"{fail_count} failed authentication attempts from {source_ip} for user '{username}' "
                f"within {time_window_seconds} seconds."
            )
            dedupe_key = (source_ip, username, ts.strftime("%Y-%m-%d %H:%M:%S"), fail_count)
            if dedupe_key in seen:
                continue
            seen.add(dedupe_key)
            alerts.append(
                make_alert(
                    detection_type="brute_force",
                    source_ip=source_ip,
                    destination_ip=None,
                    description=f"Repeated authentication failures suggest a dictionary or brute-force attack against {username}.",
                    evidence=evidence,
                    recommended_action=get_recommendation("brute_force"),
                    severity=severity,
                    timestamp=ts.strftime("%Y-%m-%d %H:%M:%S"),
                ).to_dict()
            )
    return alerts
