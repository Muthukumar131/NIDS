from __future__ import annotations

import csv
from datetime import datetime, timedelta
from pathlib import Path

from scapy.all import Ether, ICMP, IP, TCP, UDP, wrpcap


def generate_sample_auth_logs(path: str | Path) -> Path:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    rows = [
        ["timestamp", "source_ip", "username", "status"],
        ["2026-10-10 09:00:00", "192.168.10.15", "admin", "FAIL"],
        ["2026-10-10 09:00:02", "192.168.10.15", "admin", "FAIL"],
        ["2026-10-10 09:00:04", "192.168.10.15", "admin", "FAIL"],
        ["2026-10-10 09:00:06", "192.168.10.15", "admin", "FAIL"],
        ["2026-10-10 09:00:08", "192.168.10.15", "admin", "FAIL"],
        ["2026-10-10 09:02:00", "10.0.0.3", "alice", "SUCCESS"],
        ["2026-10-10 09:02:10", "192.168.10.22", "jane", "FAIL"],
        ["2026-10-10 09:02:15", "192.168.10.22", "jane", "FAIL"],
        ["2026-10-10 09:02:18", "192.168.10.22", "jane", "FAIL"],
        ["2026-10-10 09:02:20", "192.168.10.22", "jane", "SUCCESS"],
        ["2026-10-10 09:05:10", "10.0.0.9", "ops", "FAIL"],
        ["2026-10-10 09:05:14", "10.0.0.9", "ops", "FAIL"],
        ["2026-10-10 09:05:20", "10.0.0.9", "ops", "SUCCESS"],
    ]
    with target.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerows(rows)
    return target


def generate_sample_vpn_logs(path: str | Path) -> Path:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    rows = [
        ["timestamp", "source_ip", "username", "event_type", "status"],
        ["2026-10-10 18:00:00", "203.0.113.10", "alice", "LOGIN", "SUCCESS"],
        ["2026-10-10 18:01:00", "203.0.113.10", "alice", "CONNECT", "SUCCESS"],
        ["2026-10-10 18:02:00", "203.0.113.10", "alice", "AUTH_FAILURE", "FAIL"],
        ["2026-10-10 18:02:20", "203.0.113.10", "alice", "AUTH_FAILURE", "FAIL"],
        ["2026-10-10 18:02:40", "203.0.113.10", "alice", "AUTH_FAILURE", "FAIL"],
        ["2026-10-10 18:03:00", "203.0.113.10", "alice", "LOGIN", "SUCCESS"],
        ["2026-10-10 18:10:00", "198.51.100.8", "bob", "CONNECT", "SUCCESS"],
        ["2026-10-10 18:10:05", "198.51.100.8", "bob", "DISCONNECT", "SUCCESS"],
        ["2026-10-10 18:10:15", "198.51.100.8", "bob", "CONNECT", "SUCCESS"],
        ["2026-10-10 18:10:25", "198.51.100.8", "bob", "DISCONNECT", "SUCCESS"],
        ["2026-10-10 18:10:35", "198.51.100.8", "bob", "CONNECT", "SUCCESS"],
        ["2026-10-10 18:10:45", "198.51.100.8", "bob", "DISCONNECT", "SUCCESS"],
        ["2026-10-10 00:40:00", "192.0.2.44", "carol", "LOGIN", "SUCCESS"],
        ["2026-10-10 00:41:00", "192.0.2.44", "carol", "LOGIN", "SUCCESS"],
        ["2026-10-10 00:42:00", "192.0.2.44", "carol", "LOGIN", "SUCCESS"],
    ]
    with target.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerows(rows)
    return target


def generate_sample_pcap(path: str | Path) -> Path:
    packets = []
    base = datetime(2026, 10, 10, 10, 0, 0)
    for idx in range(5):
        packets.append(Ether()/IP(src="10.0.0.5", dst="10.0.0.8")/TCP(sport=12345, dport=80, flags="S"))
    for port in range(20, 35):
        packets.append(Ether()/IP(src="10.0.0.77", dst="10.0.0.10")/TCP(sport=5000, dport=port, flags="S"))
    for idx in range(3):
        packets.append(Ether()/IP(src="10.0.0.12", dst="10.0.0.20")/UDP(sport=9999, dport=53))
    packets.append(Ether()/IP(src="10.0.0.77", dst="10.0.0.10")/ICMP(type=8, id=1))
    packets.append(Ether()/IP(src="10.0.0.30", dst="10.0.0.8")/TCP(sport=4321, dport=22, flags="S"))
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(target), packets)
    return target


def generate_sample_data(base_dir: str | Path) -> dict[str, Path]:
    base = Path(base_dir)
    auth = generate_sample_auth_logs(base / "data" / "sample_auth_logs.csv")
    vpn = generate_sample_vpn_logs(base / "data" / "sample_vpn_logs.csv")
    pcap = generate_sample_pcap(base / "data" / "sample_capture.pcap")
    return {"auth": auth, "vpn": vpn, "pcap": pcap}


if __name__ == "__main__":
    generate_sample_data(Path(__file__).resolve().parent.parent)
