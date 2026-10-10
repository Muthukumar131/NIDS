from __future__ import annotations

from collections import Counter
from datetime import datetime
from io import BytesIO
from pathlib import Path

from scapy.all import PcapReader, TCP, UDP, ICMP, IP, IPv6, Raw


def _safe_get(pkt, path, default=None):
    try:
        value = pkt
        for part in path.split("."):
            if isinstance(value, dict):
                value = value.get(part, default)
            else:
                value = getattr(value, part, default)
        return value
    except Exception:
        return default


def parse_timestamp(value):
    if value is None:
        return None
    if isinstance(value, datetime):
        return value
    try:
        return datetime.strptime(str(value), "%Y-%m-%d %H:%M:%S")
    except ValueError:
        try:
            return datetime.fromisoformat(str(value))
        except ValueError:
            return None


def normalize_protocol(pkt) -> str:
    if IP in pkt:
        ip_layer = pkt[IP]
        if TCP in pkt:
            return "TCP"
        if UDP in pkt:
            return "UDP"
        if ICMP in pkt:
            return "ICMP"
        return "IPv4"
    if IPv6 in pkt:
        if TCP in pkt:
            return "TCP"
        if UDP in pkt:
            return "UDP"
        if ICMP in pkt:
            return "ICMP"
        return "IPv6"
    return "OTHER"


def packet_to_event(pkt, index: int = 0) -> dict:
    timestamp = None
    if hasattr(pkt, 'time'):
        try:
            timestamp = datetime.utcfromtimestamp(float(pkt.time))
        except (TypeError, ValueError):
            timestamp = datetime.utcnow()
    else:
        timestamp = datetime.utcnow()

    source_ip = _safe_get(pkt, "src", "unknown")
    destination_ip = _safe_get(pkt, "dst", "unknown")
    source_port = _safe_get(pkt[TCP], "sport", None) if TCP in pkt else (_safe_get(pkt[UDP], "sport", None) if UDP in pkt else None)
    destination_port = _safe_get(pkt[TCP], "dport", None) if TCP in pkt else (_safe_get(pkt[UDP], "dport", None) if UDP in pkt else None)
    proto = normalize_protocol(pkt)
    tcp_flags = ""
    if TCP in pkt:
        tcp_flags = str(pkt[TCP].flags)
    packet_length = len(bytes(pkt)) if pkt else 0

    return {
        "timestamp": timestamp.strftime("%Y-%m-%d %H:%M:%S"),
        "source_ip": str(source_ip) if source_ip is not None else "unknown",
        "destination_ip": str(destination_ip) if destination_ip is not None else "unknown",
        "source_port": int(source_port) if source_port is not None else None,
        "destination_port": int(destination_port) if destination_port is not None else None,
        "protocol": proto,
        "tcp_flags": tcp_flags,
        "packet_length": packet_length,
        "packet_index": index,
    }


def analyze_pcap_file(file_path: str | Path, max_packets: int = 20000) -> tuple[dict, list[dict]]:
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"PCAP file not found: {path}")

    if path.stat().st_size > 50 * 1024 * 1024:
        raise ValueError("This PCAP file is too large for local analysis in this prototype.")

    events: list[dict] = []
    packet_count = 0
    source_ips: set[str] = set()
    destination_ips: set[str] = set()
    protocol_counter: Counter[str] = Counter()

    with PcapReader(str(path)) as reader:
        for index, pkt in enumerate(reader):
            if index >= max_packets:
                break
            packet_count += 1
            event = packet_to_event(pkt, index)
            events.append(event)
            source_ips.add(event["source_ip"])
            destination_ips.add(event["destination_ip"])
            protocol_counter[event["protocol"]] += 1

    summary = {
        "total_packets": packet_count,
        "unique_source_ips": len(source_ips - {"unknown"}),
        "unique_destination_ips": len(destination_ips - {"unknown"}),
        "protocol_distribution": dict(protocol_counter),
        "file_name": path.name,
        "file_size_bytes": path.stat().st_size,
    }
    return summary, events
