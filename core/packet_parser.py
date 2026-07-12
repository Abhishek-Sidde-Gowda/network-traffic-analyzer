"""
Parse raw packets (from pcap file or live capture) into structured flow records.
"""
from __future__ import annotations

import struct
import socket
from dataclasses import dataclass, field
from typing import Optional
from datetime import datetime

try:
    import dpkt
    HAS_DPKT = True
except ImportError:
    HAS_DPKT = False

try:
    from scapy.all import rdpcap, PcapReader, IP, IPv6, TCP, UDP, ICMP, Raw
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False


@dataclass
class Packet:
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str          # TCP / UDP / ICMP / OTHER
    length: int
    payload_len: int
    flags: dict            # TCP flags dict or {}
    ttl: int
    ip_version: int        # 4 or 6


@dataclass
class Flow:
    """5-tuple flow aggregated from packets."""
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    packets: list[Packet] = field(default_factory=list)

    # Derived stats — populated by FlowAggregator
    start_time: float = 0.0
    end_time: float = 0.0
    duration: float = 0.0
    total_bytes: int = 0
    total_packets: int = 0
    avg_packet_size: float = 0.0
    bytes_per_second: float = 0.0
    packets_per_second: float = 0.0
    syn_count: int = 0
    fin_count: int = 0
    rst_count: int = 0
    psh_count: int = 0
    ack_count: int = 0
    unique_ttls: int = 0
    payload_ratio: float = 0.0   # avg payload / total length


def _proto_name(proto_num: int) -> str:
    return {6: "TCP", 17: "UDP", 1: "ICMP", 58: "ICMPv6"}.get(proto_num, "OTHER")


def parse_pcap_dpkt(path: str) -> list[Packet]:
    packets: list[Packet] = []
    with open(path, "rb") as f:
        try:
            cap = dpkt.pcap.Reader(f)
        except Exception:
            f.seek(0)
            cap = dpkt.pcapng.Reader(f)
        for ts, buf in cap:
            try:
                eth = dpkt.ethernet.Ethernet(buf)
                ip = eth.data
                if not isinstance(ip, (dpkt.ip.IP, dpkt.ip6.IP6)):
                    continue
                version = 4 if isinstance(ip, dpkt.ip.IP) else 6
                src_ip = socket.inet_ntop(socket.AF_INET if version == 4 else socket.AF_INET6, ip.src)
                dst_ip = socket.inet_ntop(socket.AF_INET if version == 4 else socket.AF_INET6, ip.dst)
                proto = _proto_name(ip.p)
                ttl = ip.ttl if version == 4 else ip.hlim
                transport = ip.data
                src_port = dst_port = 0
                flags = {}
                payload_len = 0
                if isinstance(transport, dpkt.tcp.TCP):
                    src_port, dst_port = transport.sport, transport.dport
                    f_raw = transport.flags
                    flags = {
                        "SYN": bool(f_raw & dpkt.tcp.TH_SYN),
                        "ACK": bool(f_raw & dpkt.tcp.TH_ACK),
                        "FIN": bool(f_raw & dpkt.tcp.TH_FIN),
                        "RST": bool(f_raw & dpkt.tcp.TH_RST),
                        "PSH": bool(f_raw & dpkt.tcp.TH_PUSH),
                    }
                    payload_len = len(transport.data)
                elif isinstance(transport, dpkt.udp.UDP):
                    src_port, dst_port = transport.sport, transport.dport
                    payload_len = len(transport.data)
                packets.append(Packet(
                    timestamp=float(ts),
                    src_ip=src_ip, dst_ip=dst_ip,
                    src_port=src_port, dst_port=dst_port,
                    protocol=proto, length=len(buf),
                    payload_len=payload_len, flags=flags,
                    ttl=ttl, ip_version=version,
                ))
            except Exception:
                continue
    return packets


def parse_pcap_scapy(path: str) -> list[Packet]:
    packets: list[Packet] = []
    for pkt in PcapReader(path):
        try:
            ts = float(pkt.time)
            if IP in pkt:
                ip_layer = pkt[IP]
                version = 4
            elif IPv6 in pkt:
                ip_layer = pkt[IPv6]
                version = 6
            else:
                continue
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            ttl = getattr(ip_layer, "ttl", getattr(ip_layer, "hlim", 0))
            proto = _proto_name(ip_layer.proto)
            src_port = dst_port = 0
            flags = {}
            payload_len = 0
            if TCP in pkt:
                tcp = pkt[TCP]
                src_port, dst_port = tcp.sport, tcp.dport
                f = tcp.flags
                flags = {
                    "SYN": bool(f & 0x02), "ACK": bool(f & 0x10),
                    "FIN": bool(f & 0x01), "RST": bool(f & 0x04),
                    "PSH": bool(f & 0x08),
                }
                payload_len = len(bytes(tcp.payload)) if tcp.payload else 0
            elif UDP in pkt:
                udp = pkt[UDP]
                src_port, dst_port = udp.sport, udp.dport
                payload_len = len(bytes(udp.payload)) if udp.payload else 0
            packets.append(Packet(
                timestamp=ts, src_ip=src_ip, dst_ip=dst_ip,
                src_port=src_port, dst_port=dst_port,
                protocol=proto, length=len(pkt),
                payload_len=payload_len, flags=flags,
                ttl=ttl, ip_version=version,
            ))
        except Exception:
            continue
    return packets


def parse_pcap(path: str) -> list[Packet]:
    if HAS_DPKT:
        try:
            return parse_pcap_dpkt(path)
        except Exception:
            pass
    if HAS_SCAPY:
        return parse_pcap_scapy(path)
    raise RuntimeError("Neither dpkt nor scapy is available. Install one: pip install dpkt scapy")
