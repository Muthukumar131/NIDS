import csv
import json
from datetime import datetime
from pathlib import Path
from typing import Iterable


ALLOWED_UPLOAD_EXTENSIONS = {
    ".pcap",
    ".pcapng",
    ".csv",
    ".json",
}


def validate_upload(file_name: str, file_size_bytes: int, max_size_mb: int = 50) -> None:
    if file_name is None or not str(file_name).strip():
        raise ValueError("No file name was provided.")

    suffix = Path(file_name).suffix.lower()
    if suffix not in ALLOWED_UPLOAD_EXTENSIONS:
        raise ValueError(f"Unsupported file type: {suffix or 'unknown'}")

    if file_size_bytes <= 0:
        raise ValueError("The uploaded file is empty.")

    if file_size_bytes > max_size_mb * 1024 * 1024:
        raise ValueError(f"The file exceeds the {max_size_mb} MB upload limit.")


def safe_write_text(path: str | Path, content: str) -> Path:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")
    return target


def unique_report_path(directory: str | Path, stem: str, suffix: str) -> Path:
    base_dir = Path(directory)
    base_dir.mkdir(parents=True, exist_ok=True)
    candidate = base_dir / f"{stem}{suffix}"
    counter = 1
    while candidate.exists():
        candidate = base_dir / f"{stem}_{counter}{suffix}"
        counter += 1
    return candidate


def export_alerts_csv(alerts: Iterable[dict], path: str | Path) -> Path:
    export_path = Path(path)
    export_path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "alert_id",
        "detection_type",
        "timestamp",
        "source_ip",
        "destination_ip",
        "severity",
        "description",
        "evidence",
        "recommended_action",
    ]

    alert_rows = list(alerts)
    with export_path.open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        for alert in alert_rows:
            writer.writerow({key: alert.get(key, "") for key in fieldnames})
    return export_path


def export_alerts_json(alerts: Iterable[dict], path: str | Path) -> Path:
    export_path = Path(path)
    export_path.parent.mkdir(parents=True, exist_ok=True)
    alert_rows = list(alerts)
    payload = {
        "generated_at": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
        "total_alerts": len(alert_rows),
        "alerts": alert_rows,
    }
    export_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    return export_path


def load_csv_rows(path: str | Path) -> list[dict]:
    safe_path = Path(path)
    if not safe_path.exists():
        raise FileNotFoundError(f"CSV file not found: {safe_path}")

    rows: list[dict] = []
    with safe_path.open("r", newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            cleaned = {str(key).strip(): value for key, value in row.items() if key is not None}
            rows.append(cleaned)
    return rows


def load_json_rows(path: str | Path) -> list[dict]:
    safe_path = Path(path)
    if not safe_path.exists():
        raise FileNotFoundError(f"JSON file not found: {safe_path}")
    payload = json.loads(safe_path.read_text(encoding="utf-8"))
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict) and isinstance(payload.get("alerts"), list):
        return payload["alerts"]
    return []
