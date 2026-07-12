"""
Signature-based detection rules that run alongside the ML anomaly detector.
Each rule returns a list of Alert dicts for matching flows.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable


@dataclass
class Alert:
    rule_name: str
    severity: str          # CRITICAL / HIGH / MEDIUM / LOW
    description: str
    flow: dict
    indicators: dict = field(default_factory=dict)


RuleFn = Callable[[dict], Alert | None]
RULES: list[tuple[str, RuleFn]] = []


def rule(fn: RuleFn) -> RuleFn:
    RULES.append((fn.__name__, fn))
    return fn


# ── Port scan detection ──────────────────────────────────────────────────────

@rule
def port_scan(flow: dict) -> Alert | None:
    """High SYN / low ACK ratio on many unique dst ports = horizontal scan."""
    if flow.get("protocol") != "TCP":
        return None
    tp = flow.get("total_packets", 0)
    if tp < 5:
        return None
    syn_r = flow.get("syn_ratio", 0)
    ack_r = flow.get("ack_ratio", 0)
    if syn_r > 0.7 and ack_r < 0.3:
        return Alert(
            rule_name="port_scan",
            severity="HIGH",
            description=f"Possible port scan: SYN ratio {syn_r:.2f}, ACK ratio {ack_r:.2f}",
            flow=flow,
            indicators={"syn_ratio": syn_r, "ack_ratio": ack_r},
        )
    return None


# ── SYN flood ────────────────────────────────────────────────────────────────

@rule
def syn_flood(flow: dict) -> Alert | None:
    if flow.get("protocol") != "TCP":
        return None
    pps = flow.get("packets_per_second", 0)
    syn_r = flow.get("syn_ratio", 0)
    if pps > 500 and syn_r > 0.8:
        return Alert(
            rule_name="syn_flood",
            severity="CRITICAL",
            description=f"SYN flood: {pps:.0f} pkt/s, SYN ratio {syn_r:.2f}",
            flow=flow,
            indicators={"pps": pps, "syn_ratio": syn_r},
        )
    return None


# ── Data exfiltration (large outbound) ───────────────────────────────────────

@rule
def data_exfiltration(flow: dict) -> Alert | None:
    bps = flow.get("bytes_per_second", 0)
    total_bytes = flow.get("total_bytes", 0)
    dst_port = flow.get("dst_port", 0)
    # Flagged: sustained high-volume to unusual port (not 80/443/22)
    if total_bytes > 50_000_000 and dst_port not in (80, 443, 22, 21, 25, 53):
        return Alert(
            rule_name="data_exfiltration",
            severity="HIGH",
            description=f"Possible exfil: {total_bytes/1e6:.1f} MB to port {dst_port}",
            flow=flow,
            indicators={"total_bytes": total_bytes, "dst_port": dst_port},
        )
    return None


# ── DNS tunnelling ────────────────────────────────────────────────────────────

@rule
def dns_tunnelling(flow: dict) -> Alert | None:
    if flow.get("dst_port") != 53 and flow.get("src_port") != 53:
        return None
    avg = flow.get("avg_packet_size", 0)
    bps = flow.get("bytes_per_second", 0)
    if avg > 400 and bps > 5000:
        return Alert(
            rule_name="dns_tunnelling",
            severity="HIGH",
            description=f"Possible DNS tunnel: avg pkt {avg:.0f} B, {bps:.0f} Bps",
            flow=flow,
            indicators={"avg_packet_size": avg, "bps": bps},
        )
    return None


# ── ICMP flood ────────────────────────────────────────────────────────────────

@rule
def icmp_flood(flow: dict) -> Alert | None:
    if flow.get("protocol") not in ("ICMP", "ICMPv6"):
        return None
    pps = flow.get("packets_per_second", 0)
    if pps > 200:
        return Alert(
            rule_name="icmp_flood",
            severity="HIGH",
            description=f"ICMP flood: {pps:.0f} pkt/s",
            flow=flow,
            indicators={"pps": pps},
        )
    return None


# ── Brute force (many small TCP flows, same dst) ─────────────────────────────

@rule
def brute_force_ssh(flow: dict) -> Alert | None:
    if flow.get("dst_port") not in (22, 23, 3389, 5900):
        return None
    rst_r = flow.get("rst_ratio", 0)
    tp = flow.get("total_packets", 0)
    if tp > 10 and rst_r > 0.3:
        port_name = {22: "SSH", 23: "Telnet", 3389: "RDP", 5900: "VNC"}.get(
            flow["dst_port"], str(flow["dst_port"])
        )
        return Alert(
            rule_name="brute_force",
            severity="HIGH",
            description=f"Possible {port_name} brute force: RST ratio {rst_r:.2f}",
            flow=flow,
            indicators={"dst_port": flow["dst_port"], "rst_ratio": rst_r},
        )
    return None


# ── Beaconing (regular small outbound) ───────────────────────────────────────

@rule
def beaconing(flow: dict) -> Alert | None:
    duration = flow.get("duration", 0)
    tp = flow.get("total_packets", 0)
    avg = flow.get("avg_packet_size", 0)
    if duration > 300 and tp > 20 and avg < 200:
        # Very regular small packets over a long time = possible C2 beacon
        pps = flow.get("packets_per_second", 0)
        if 0.01 < pps < 1.0:
            return Alert(
                rule_name="beaconing",
                severity="MEDIUM",
                description=f"Possible C2 beacon: {pps:.3f} pkt/s over {duration:.0f}s",
                flow=flow,
                indicators={"pps": pps, "duration": duration},
            )
    return None


def run_all_rules(flow: dict) -> list[Alert]:
    alerts = []
    for _name, fn in RULES:
        try:
            result = fn(flow)
            if result:
                alerts.append(result)
        except Exception:
            pass
    return alerts


def apply_rules(flows: list[dict]) -> list[Alert]:
    all_alerts = []
    for flow in flows:
        all_alerts.extend(run_all_rules(flow))
    return all_alerts
