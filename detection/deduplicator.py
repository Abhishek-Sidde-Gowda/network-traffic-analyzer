"""
Alert deduplicator — collapses repeated alerts of the same rule+src_ip
into a single alert with a count, reducing noise in the output.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from .rules import Alert


@dataclass
class DeduplicatedAlert:
    rule_name: str
    severity: str
    description: str
    src_ip: str
    dst_ip: str
    dst_port: int
    count: int
    indicators: dict = field(default_factory=dict)


def deduplicate(alerts: list[Alert], group_by: tuple = ("rule_name", "src_ip", "dst_port")) -> list[DeduplicatedAlert]:
    """
    Group alerts by (rule_name, src_ip, dst_port) and collapse duplicates.
    Returns list sorted by severity then count descending.
    """
    SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    groups: dict[tuple, list[Alert]] = {}

    for alert in alerts:
        key = tuple(
            alert.rule_name if g == "rule_name"
            else alert.flow.get("src_ip", "") if g == "src_ip"
            else alert.flow.get("dst_port", 0)
            for g in group_by
        )
        groups.setdefault(key, []).append(alert)

    result = []
    for key, group in groups.items():
        rep = group[0]
        result.append(DeduplicatedAlert(
            rule_name=rep.rule_name,
            severity=rep.severity,
            description=rep.description,
            src_ip=rep.flow.get("src_ip", ""),
            dst_ip=rep.flow.get("dst_ip", ""),
            dst_port=rep.flow.get("dst_port", 0),
            count=len(group),
            indicators=rep.indicators,
        ))

    result.sort(key=lambda a: (SEV_ORDER.get(a.severity, 9), -a.count))
    return result
