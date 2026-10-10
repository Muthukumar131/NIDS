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


def detect_vpn_anomalies(log_rows, auth_failure_threshold: int = 3, repeated_disconnect_threshold: int = 3, unusual_login_hours: tuple[int, int] = (0, 6), time_window_seconds: int = 600):
    if not log_rows:
        return []

    alerts = []
    failures_by_user: dict[tuple[str, str], list[datetime]] = defaultdict(list)
    logins_by_user: dict[str, list[datetime]] = defaultdict(list)
    disconnects_by_ip: dict[str, list[datetime]] = defaultdict(list)

    for row in log_rows:
        if not isinstance(row, dict):
            continue
        ts = _coerce_timestamp(row.get("timestamp"))
        source_ip = str(row.get("source_ip") or "").strip() or "unknown"
        username = str(row.get("username") or "unknown").strip()
        event_type = str(row.get("event_type") or "").upper().strip()
        status = str(row.get("status") or "").upper().strip()
        if ts is None:
            continue

        if event_type in {"AUTH_FAILURE", "LOGIN_FAILURE", "FAILED_LOGIN"} or status in {"FAIL", "FAILED", "AUTH_FAILURE"}:
            failures_by_user[(source_ip, username)].append(ts)
        if event_type == "LOGIN" or status == "SUCCESS":
            logins_by_user[username].append(ts)
        if event_type in {"DISCONNECT", "LOGOUT"}:
            disconnects_by_ip[source_ip].append(ts)

    for (source_ip, username), times in failures_by_user.items():
        times.sort()
        for idx, ts in enumerate(times):
            window = [t for t in times[idx:] if (t - ts).total_seconds() <= time_window_seconds]
            if len(window) >= auth_failure_threshold:
                severity = severity_from_threshold(len(window), auth_failure_threshold, auth_failure_threshold + 2)
                alerts.append(
                    make_alert(
                        detection_type="vpn_auth_failure",
                        source_ip=source_ip,
                        destination_ip=None,
                        description=f"Repeated VPN authentication failures for user '{username}' indicate suspicious access behavior.",
                        evidence=f"{len(window)} authentication failures for {username} from {source_ip} within {time_window_seconds} seconds.",
                        recommended_action=get_recommendation("vpn_auth_failure"),
                        severity=severity,
                        timestamp=ts.strftime("%Y-%m-%d %H:%M:%S"),
                    ).to_dict()
                )

    for username, times in logins_by_user.items():
        times.sort()
        for ts in times:
            relevant_failures = [
                fail_ts for fail_ts in [t for key, vals in failures_by_user.items() for t in vals if key[1] == username]
                if 0 <= (ts - fail_ts).total_seconds() <= time_window_seconds
            ]
            if relevant_failures:
                alerts.append(
                    make_alert(
                        detection_type="vpn_auth_failure",
                        source_ip="user correlation",
                        destination_ip=None,
                        description=f"A successful VPN login for '{username}' followed repeated failures; this is a correlation-based indicator and not a confirmed attack.",
                        evidence=f"Successful login at {ts.strftime('%Y-%m-%d %H:%M:%S')} followed {len(relevant_failures)} failed attempts in the previous {time_window_seconds} seconds.",
                        recommended_action=get_recommendation("vpn_auth_failure"),
                        severity="MEDIUM",
                        timestamp=ts.strftime("%Y-%m-%d %H:%M:%S"),
                    ).to_dict()
                )

    for source_ip, times in disconnects_by_ip.items():
        times.sort()
        for idx, ts in enumerate(times):
            window = [t for t in times[idx:] if (t - ts).total_seconds() <= time_window_seconds]
            if len(window) >= repeated_disconnect_threshold:
                alerts.append(
                    make_alert(
                        detection_type="vpn_repeated_disconnect",
                        source_ip=source_ip,
                        destination_ip=None,
                        description=f"Repeated VPN disconnects from {source_ip} may suggest session instability or suspicious reuse.",
                        evidence=f"{len(window)} disconnect events within {time_window_seconds} seconds.",
                        recommended_action=get_recommendation("vpn_repeated_disconnect"),
                        severity="MEDIUM",
                        timestamp=ts.strftime("%Y-%m-%d %H:%M:%S"),
                    ).to_dict()
                )

    for username, times in logins_by_user.items():
        suspicious = [ts for ts in times if unusual_login_hours[0] <= ts.hour <= unusual_login_hours[1]]
        if len(suspicious) >= 2:
            alerts.append(
                make_alert(
                    detection_type="vpn_unusual_login",
                    source_ip="user",
                    destination_ip=None,
                    description=f"User '{username}' shows repeated logins during unusual hours based on the configured baseline.",
                    evidence=f"{len(suspicious)} logins occurred during configured unusual hours: {unusual_login_hours}.",
                    recommended_action=get_recommendation("vpn_unusual_login"),
                    severity="LOW",
                    timestamp=suspicious[0].strftime("%Y-%m-%d %H:%M:%S"),
                ).to_dict()
            )

    unique = []
    seen = set()
    for alert in alerts:
        key = (alert["detection_type"], alert["source_ip"], alert["description"], alert["timestamp"])
        if key in seen:
            continue
        seen.add(key)
        unique.append(alert)
    return unique
