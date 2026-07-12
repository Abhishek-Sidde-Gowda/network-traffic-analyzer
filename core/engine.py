"""
High-level analysis engine — single entry point for CLI and web.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
import pandas as pd

import sys, os as _os
sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))

from core.packet_parser import parse_pcap, Packet
from core.flow_aggregator import aggregate_flows, flows_to_records
from ml.feature_extractor import engineer_features
from ml.anomaly_detector import AnomalyDetector
from detection.rules import apply_rules, Alert


@dataclass
class AnalysisResult:
    source: str
    total_packets: int
    total_flows: int
    anomalous_flows: int
    alerts: list[Alert]
    flow_records: list[dict]
    df: Optional[object] = None          # pandas DataFrame — populated if pandas available


def analyse_pcap(
    path: str | Path,
    contamination: float = 0.05,
    anomaly_threshold: float = 0.6,
    flow_timeout: float = 120.0,
) -> AnalysisResult:
    path = str(path)

    # 1. Parse packets
    packets: list[Packet] = parse_pcap(path)

    # 2. Aggregate into flows
    flows = aggregate_flows(packets, timeout_seconds=flow_timeout)
    records = flows_to_records(flows)

    if not records:
        return AnalysisResult(
            source=path, total_packets=len(packets),
            total_flows=0, anomalous_flows=0,
            alerts=[], flow_records=[],
        )

    # 3. Engineer features
    df_feat = engineer_features(records)

    # 4. ML anomaly scoring (train on the batch itself — unsupervised)
    detector = AnomalyDetector(contamination=contamination)
    detector.fit(records)
    scored = detector.label(records, threshold=anomaly_threshold)

    # 5. Signature rules
    alerts: list[Alert] = apply_rules(scored)

    anomalous = sum(1 for r in scored if r["anomaly_label"] == "ANOMALOUS")

    # Merge scores back into records
    for rec, score_rec in zip(records, scored):
        rec["anomaly_score"] = score_rec["anomaly_score"]
        rec["anomaly_label"] = score_rec["anomaly_label"]

    return AnalysisResult(
        source=path,
        total_packets=len(packets),
        total_flows=len(flows),
        anomalous_flows=anomalous,
        alerts=alerts,
        flow_records=records,
        df=pd.DataFrame(records),
    )
