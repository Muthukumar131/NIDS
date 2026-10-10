from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Any


SEVERITY_LEVELS = ["LOW", "MEDIUM", "HIGH"]


@dataclass
class Alert:
    alert_id: str
    detection_type: str
    timestamp: str
    source_ip: str
    destination_ip: str | None
    severity: str
    description: str
    evidence: str
    recommended_action: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def generate_alert_id(detection_type: str) -> str:
    stamp = datetime.utcnow().strftime("%Y%m%d%H%M%S%f")
    return f"{detection_type.upper()}-{stamp}"


def normalize_severity(value: str) -> str:
    cleaned = str(value or "LOW").upper()
    if cleaned not in SEVERITY_LEVELS:
        return "LOW"
    return cleaned


def severity_from_threshold(count: int, medium_threshold: int, high_threshold: int) -> str:
    if count >= high_threshold:
        return "HIGH"
    if count >= medium_threshold:
        return "MEDIUM"
    return "LOW"


def make_alert(
    detection_type: str,
    source_ip: str,
    description: str,
    evidence: str,
    recommended_action: str,
    destination_ip: str | None = None,
    severity: str = "MEDIUM",
    timestamp: str | None = None,
) -> Alert:
    return Alert(
        alert_id=generate_alert_id(detection_type),
        detection_type=detection_type,
        timestamp=timestamp or datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
        source_ip=source_ip or "unknown",
        destination_ip=destination_ip,
        severity=normalize_severity(severity),
        description=description,
        evidence=evidence,
        recommended_action=recommended_action,
    )
