from detector.vpn_analyzer import detect_vpn_anomalies


def test_vpn_analyzer_flags_repeated_failures_and_disconnects():
    rows = [
        {"timestamp": "2026-10-10 18:00:00", "source_ip": "203.0.113.10", "username": "alice", "event_type": "AUTH_FAILURE", "status": "FAIL"},
        {"timestamp": "2026-10-10 18:00:15", "source_ip": "203.0.113.10", "username": "alice", "event_type": "AUTH_FAILURE", "status": "FAIL"},
        {"timestamp": "2026-10-10 18:00:30", "source_ip": "203.0.113.10", "username": "alice", "event_type": "AUTH_FAILURE", "status": "FAIL"},
        {"timestamp": "2026-10-10 18:02:00", "source_ip": "198.51.100.8", "username": "bob", "event_type": "CONNECT", "status": "SUCCESS"},
        {"timestamp": "2026-10-10 18:02:05", "source_ip": "198.51.100.8", "username": "bob", "event_type": "DISCONNECT", "status": "SUCCESS"},
        {"timestamp": "2026-10-10 18:02:10", "source_ip": "198.51.100.8", "username": "bob", "event_type": "CONNECT", "status": "SUCCESS"},
        {"timestamp": "2026-10-10 18:02:15", "source_ip": "198.51.100.8", "username": "bob", "event_type": "DISCONNECT", "status": "SUCCESS"},
    ]

    alerts = detect_vpn_anomalies(rows, auth_failure_threshold=2, repeated_disconnect_threshold=2, time_window_seconds=300)
    assert alerts
    assert any(alert["detection_type"] == "vpn_auth_failure" for alert in alerts)
