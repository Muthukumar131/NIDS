import json
import logging
from datetime import datetime
from pathlib import Path


LOG_DIR = Path(__file__).resolve().parent.parent / "logs"
LOG_PATH = LOG_DIR / "netguard.log"


def setup_logger(name: str = "netguard") -> logging.Logger:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)
    logger.propagate = False

    if not logger.handlers:
        handler = logging.FileHandler(LOG_PATH, encoding="utf-8")
        handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
        logger.addHandler(handler)

    return logger


def log_event(event_type: str, message: str, **context) -> dict:
    logger = setup_logger()
    payload = {
        "timestamp": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
        "event_type": event_type,
        "message": message,
        **context,
    }
    logger.info(json.dumps(payload, default=str, ensure_ascii=False))
    return payload


def safe_filename(name: str) -> str:
    if not name:
        return "report"
    cleaned = "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in name)
    return cleaned.strip("._") or "report"
