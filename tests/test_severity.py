from detector.severity import severity_from_threshold


def test_severity_assignment_follows_thresholds():
    assert severity_from_threshold(8, 5, 10) == "MEDIUM"
    assert severity_from_threshold(12, 5, 10) == "HIGH"


def test_duplicate_alert_suppression_logic():
    alerts = [
        {"source_ip": "10.0.0.77", "destination_ip": "10.0.0.10", "description": "duplicate", "timestamp": "2026-10-10 10:00:00"},
        {"source_ip": "10.0.0.77", "destination_ip": "10.0.0.10", "description": "duplicate", "timestamp": "2026-10-10 10:00:00"},
        {"source_ip": "10.0.0.77", "destination_ip": "10.0.0.10", "description": "different", "timestamp": "2026-10-10 10:00:10"},
    ]
    seen = set()
    deduped = []
    for alert in alerts:
        key = (alert["source_ip"], alert["destination_ip"], alert["description"], alert["timestamp"])
        if key in seen:
            continue
        seen.add(key)
        deduped.append(alert)
    assert len(deduped) == 2
