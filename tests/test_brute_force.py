from detector.brute_force import detect_brute_force


def test_brute_force_detects_repeated_failures():
    rows = [
        {"timestamp": "2026-10-10 10:00:00", "source_ip": "192.168.1.20", "username": "admin", "status": "FAIL"},
        {"timestamp": "2026-10-10 10:00:03", "source_ip": "192.168.1.20", "username": "admin", "status": "FAIL"},
        {"timestamp": "2026-10-10 10:00:06", "source_ip": "192.168.1.20", "username": "admin", "status": "FAIL"},
        {"timestamp": "2026-10-10 10:00:09", "source_ip": "192.168.1.20", "username": "admin", "status": "FAIL"},
        {"timestamp": "2026-10-10 10:00:15", "source_ip": "192.168.1.20", "username": "admin", "status": "SUCCESS"},
    ]

    alerts = detect_brute_force(rows, time_window_seconds=300, medium_threshold=3, high_threshold=5)
    assert alerts
    assert alerts[0]["detection_type"] == "brute_force"
