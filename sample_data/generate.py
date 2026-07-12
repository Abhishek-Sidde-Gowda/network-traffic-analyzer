"""
Generate a synthetic .pcap file with mixed normal + attack traffic.
Requires scapy: pip install scapy
"""
from __future__ import annotations

import random
import struct
import time
import os
from pathlib import Path

OUTPUT = Path(__file__).parent / "sample_traffic.pcap"

try:
    from scapy.all import (
        Ether, IP, IPv6, TCP, UDP, ICMP, Raw, wrpcap, RandIP, RandShort
    )
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False


def _ts(base: float, offset: float) -> float:
    return base + offset


def gen_normal_http(base_ts: float, n: int = 200) -> list:
    pkts = []
    for i in range(n):
        src = f"10.0.{random.randint(0,5)}.{random.randint(2,254)}"
        sport = random.randint(1024, 65535)
        t = base_ts + i * random.uniform(0.05, 0.5)
        pkts.append(
            Ether() / IP(src=src, dst="93.184.216.34", ttl=64) /
            TCP(sport=sport, dport=80, flags="S") /
            Raw(load=b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
        )
        pkts[-1].time = t
    return pkts


def gen_normal_dns(base_ts: float, n: int = 100) -> list:
    pkts = []
    for i in range(n):
        src = f"192.168.1.{random.randint(2, 50)}"
        t = base_ts + i * random.uniform(0.1, 1.0)
        payload = b"\x00\x01" * 20  # fake DNS query
        pkts.append(
            Ether() / IP(src=src, dst="8.8.8.8", ttl=64) /
            UDP(sport=random.randint(1024, 65535), dport=53) /
            Raw(load=payload)
        )
        pkts[-1].time = t
    return pkts


def gen_port_scan(base_ts: float, n: int = 300) -> list:
    pkts = []
    attacker = "172.16.99.1"
    victim = "10.0.0.5"
    for i in range(n):
        t = base_ts + i * 0.01
        pkts.append(
            Ether() / IP(src=attacker, dst=victim, ttl=128) /
            TCP(sport=random.randint(40000, 60000), dport=i % 1024 + 1, flags="S")
        )
        pkts[-1].time = t
    return pkts


def gen_syn_flood(base_ts: float, n: int = 500) -> list:
    pkts = []
    victim = "10.0.0.10"
    for i in range(n):
        src = f"203.0.{random.randint(0,255)}.{random.randint(1,254)}"
        t = base_ts + i * 0.002
        pkts.append(
            Ether() / IP(src=src, dst=victim, ttl=64) /
            TCP(sport=random.randint(1024, 65535), dport=80, flags="S")
        )
        pkts[-1].time = t
    return pkts


def gen_dns_tunnel(base_ts: float, n: int = 150) -> list:
    pkts = []
    attacker = "10.1.2.3"
    for i in range(n):
        t = base_ts + i * 0.2
        payload = os.urandom(450)  # large DNS = tunnel indicator
        pkts.append(
            Ether() / IP(src=attacker, dst="8.8.8.8", ttl=64) /
            UDP(sport=random.randint(1024, 65535), dport=53) /
            Raw(load=payload)
        )
        pkts[-1].time = t
    return pkts


def gen_beacon(base_ts: float, n: int = 100) -> list:
    pkts = []
    infected = "10.0.1.55"
    c2 = "185.220.101.45"
    for i in range(n):
        t = base_ts + i * 30 + random.uniform(-2, 2)  # every 30s ± jitter
        pkts.append(
            Ether() / IP(src=infected, dst=c2, ttl=64) /
            TCP(sport=random.randint(1024, 65535), dport=443, flags="PA") /
            Raw(load=b"\x00" * random.randint(64, 128))
        )
        pkts[-1].time = t
    return pkts


def main():
    if not HAS_SCAPY:
        print("scapy not installed — cannot generate sample pcap. pip install scapy")
        return

    base = time.time() - 3600
    all_pkts = []
    all_pkts += gen_normal_http(base)
    all_pkts += gen_normal_dns(base + 5)
    all_pkts += gen_port_scan(base + 60)
    all_pkts += gen_syn_flood(base + 120)
    all_pkts += gen_dns_tunnel(base + 200)
    all_pkts += gen_beacon(base + 300)

    all_pkts.sort(key=lambda p: float(p.time))
    wrpcap(str(OUTPUT), all_pkts)
    print(f"Written {len(all_pkts)} packets → {OUTPUT}")


if __name__ == "__main__":
    main()
