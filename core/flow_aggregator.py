"""
Aggregate packets into bidirectional flows and compute per-flow statistics.
"""
from __future__ import annotations

from collections import defaultdict
from typing import Iterator
from .packet_parser import Packet, Flow


FlowKey = tuple[str, str, int, int, str]


def _canonical_key(pkt: Packet) -> FlowKey:
    """Return a consistent (src, dst, sport, dport, proto) key regardless of direction."""
    a = (pkt.src_ip, pkt.dst_ip, pkt.src_port, pkt.dst_port)
    b = (pkt.dst_ip, pkt.src_ip, pkt.dst_port, pkt.src_port)
    lo = min(a, b)
    return (lo[0], lo[1], lo[2], lo[3], pkt.protocol)


def aggregate_flows(packets: list[Packet], timeout_seconds: float = 120.0) -> list[Flow]:
    """
    Group packets into flows using a 5-tuple + inactivity timeout.
    Returns list of completed Flow objects with statistics populated.
    """
    buckets: dict[FlowKey, Flow] = {}
    last_seen: dict[FlowKey, float] = {}
    completed: list[Flow] = []

    for pkt in sorted(packets, key=lambda p: p.timestamp):
        key = _canonical_key(pkt)
        now = pkt.timestamp

        # expire old flows
        if key in last_seen and (now - last_seen[key]) > timeout_seconds:
            completed.append(_finalize(buckets.pop(key)))
            last_seen.pop(key)

        if key not in buckets:
            flow = Flow(
                src_ip=pkt.src_ip, dst_ip=pkt.dst_ip,
                src_port=pkt.src_port, dst_port=pkt.dst_port,
                protocol=pkt.protocol,
            )
            flow.start_time = now
            buckets[key] = flow

        flow = buckets[key]
        flow.packets.append(pkt)
        last_seen[key] = now

    # flush remaining open flows
    for key, flow in buckets.items():
        completed.append(_finalize(flow))

    return completed


def _finalize(flow: Flow) -> Flow:
    pkts = flow.packets
    if not pkts:
        return flow
    flow.start_time = pkts[0].timestamp
    flow.end_time = pkts[-1].timestamp
    flow.duration = max(flow.end_time - flow.start_time, 1e-6)
    flow.total_packets = len(pkts)
    flow.total_bytes = sum(p.length for p in pkts)
    flow.avg_packet_size = flow.total_bytes / flow.total_packets
    flow.bytes_per_second = flow.total_bytes / flow.duration
    flow.packets_per_second = flow.total_packets / flow.duration
    flow.syn_count = sum(1 for p in pkts if p.flags.get("SYN"))
    flow.fin_count = sum(1 for p in pkts if p.flags.get("FIN"))
    flow.rst_count = sum(1 for p in pkts if p.flags.get("RST"))
    flow.psh_count = sum(1 for p in pkts if p.flags.get("PSH"))
    flow.ack_count = sum(1 for p in pkts if p.flags.get("ACK"))
    flow.unique_ttls = len(set(p.ttl for p in pkts))
    total_payload = sum(p.payload_len for p in pkts)
    flow.payload_ratio = total_payload / max(flow.total_bytes, 1)
    return flow


def flows_to_records(flows: list[Flow]) -> list[dict]:
    """Convert flows to flat dicts suitable for pandas / ML feature extraction."""
    records = []
    for f in flows:
        records.append({
            "src_ip": f.src_ip,
            "dst_ip": f.dst_ip,
            "src_port": f.src_port,
            "dst_port": f.dst_port,
            "protocol": f.protocol,
            "duration": f.duration,
            "total_bytes": f.total_bytes,
            "total_packets": f.total_packets,
            "avg_packet_size": f.avg_packet_size,
            "bytes_per_second": f.bytes_per_second,
            "packets_per_second": f.packets_per_second,
            "syn_count": f.syn_count,
            "fin_count": f.fin_count,
            "rst_count": f.rst_count,
            "psh_count": f.psh_count,
            "ack_count": f.ack_count,
            "unique_ttls": f.unique_ttls,
            "payload_ratio": f.payload_ratio,
            "start_time": f.start_time,
        })
    return records
