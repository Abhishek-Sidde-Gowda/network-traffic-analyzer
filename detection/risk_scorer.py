"""
Composite risk scorer — combines ML anomaly score with signature rule weight
to produce a single RISK_SCORE in [0, 100] and a RISK_LEVEL label.

Formula:
    risk = 0.5 * (anomaly_score * 100)
          + 0.5 * (max_rule_weight)
    clamped to [0, 100]
"""
from __future__ import annotations

from .rules import Alert

SEVERITY_WEIGHTS = {
    "CRITICAL": 100,
    "HIGH": 75,
    "MEDIUM": 45,
    "LOW": 20,
}

RISK_LEVELS = [
    (80, "CRITICAL"),
    (60, "HIGH"),
    (35, "MEDIUM"),
    (0,  "LOW"),
]


def score_flow(flow: dict, alerts: list[Alert]) -> dict:
    """
    Enrich a single flow record with risk_score and risk_level.
    alerts should be the subset of alerts that match this flow.
    """
    anomaly = flow.get("anomaly_score", 0.0)
    ml_component = anomaly * 100 * 0.5

    flow_alerts = [
        a for a in alerts
        if a.flow.get("src_ip") == flow.get("src_ip")
        and a.flow.get("dst_ip") == flow.get("dst_ip")
        and a.flow.get("dst_port") == flow.get("dst_port")
    ]
    max_weight = max((SEVERITY_WEIGHTS.get(a.severity, 0) for a in flow_alerts), default=0)
    rule_component = max_weight * 0.5

    risk = min(100, ml_component + rule_component)

    level = "LOW"
    for threshold, label in RISK_LEVELS:
        if risk >= threshold:
            level = label
            break

    flow["risk_score"] = round(risk, 1)
    flow["risk_level"] = level
    flow["matched_rules"] = [a.rule_name for a in flow_alerts]
    return flow


def score_all(flows: list[dict], alerts: list[Alert]) -> list[dict]:
    return [score_flow(f, alerts) for f in flows]
