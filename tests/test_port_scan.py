from detector.port_scan import detect_port_scan


def test_port_scan_detects_multiple_ports_in_window():
    events = [
        {"timestamp": "2026-10-10 10:00:00", "source_ip": "10.0.0.5", "destination_ip": "10.0.0.10", "destination_port": 22},
        {"timestamp": "2026-10-10 10:00:01", "source_ip": "10.0.0.5", "destination_ip": "10.0.0.10", "destination_port": 23},
        {"timestamp": "2026-10-10 10:00:02", "source_ip": "10.0.0.5", "destination_ip": "10.0.0.10", "destination_port": 80},
        {"timestamp": "2026-10-10 10:00:03", "source_ip": "10.0.0.5", "destination_ip": "10.0.0.10", "destination_port": 443},
        {"timestamp": "2026-10-10 10:00:04", "source_ip": "10.0.0.5", "destination_ip": "10.0.0.10", "destination_port": 8080},
        {"timestamp": "2026-10-10 10:00:05", "source_ip": "10.0.0.5", "destination_ip": "10.0.0.10", "destination_port": 3306},
        {"timestamp": "2026-10-10 10:00:06", "source_ip": "10.0.0.5", "destination_ip": "10.0.0.10", "destination_port": 3389},
        {"timestamp": "2026-10-10 10:00:07", "source_ip": "10.0.0.5", "destination_ip": "10.0.0.10", "destination_port": 5900},
        {"timestamp": "2026-10-10 10:00:08", "source_ip": "10.0.0.5", "destination_ip": "10.0.0.10", "destination_port": 21},
        {"timestamp": "2026-10-10 10:00:09", "source_ip": "10.0.0.5", "destination_ip": "10.0.0.10", "destination_port": 25},
        {"timestamp": "2026-10-10 10:00:10", "source_ip": "10.0.0.5", "destination_ip": "10.0.0.10", "destination_port": 110},
    ]

    alerts = detect_port_scan(events, medium_threshold=5, high_threshold=8, time_window_seconds=10)
    assert alerts
    assert alerts[0]["severity"] in {"MEDIUM", "HIGH"}
    assert alerts[0]["detection_type"] == "port_scan"
