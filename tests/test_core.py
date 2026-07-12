"""
Unit tests for core pipeline — no pcap files needed, uses synthetic data.
Run: python -m pytest tests/ -v
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
import time
from core.packet_parser import Packet
from core.flow_aggregator import aggregate_flows, flows_to_records
from ml.feature_extractor import engineer_features, build_feature_matrix
from ml.anomaly_detector import AnomalyDetector
from detection.rules import apply_rules, Alert


def _make_packet(src="1.1.1.1", dst="2.2.2.2", sport=1234, dport=80,
                 proto="TCP", flags=None, ts=None, length=100, payload=50):
    return Packet(
        timestamp=ts or time.time(),
        src_ip=src, dst_ip=dst,
        src_port=sport, dst_port=dport,
        protocol=proto, length=length,
        payload_len=payload, flags=flags or {},
        ttl=64, ip_version=4,
    )


class TestFlowAggregation:
    def test_single_flow(self):
        base = time.time()
        pkts = [_make_packet(ts=base + i) for i in range(5)]
        flows = aggregate_flows(pkts)
        assert len(flows) == 1
        assert flows[0].total_packets == 5

    def test_two_flows_different_ip(self):
        base = time.time()
        pkts = (
            [_make_packet(src="1.1.1.1", ts=base + i) for i in range(3)] +
            [_make_packet(src="3.3.3.3", ts=base + i) for i in range(3)]
        )
        flows = aggregate_flows(pkts)
        assert len(flows) == 2

    def test_timeout_splits_flows(self):
        base = time.time()
        pkts = (
            [_make_packet(ts=base)] +
            [_make_packet(ts=base + 200)]  # 200s gap > 120s timeout
        )
        flows = aggregate_flows(pkts, timeout_seconds=120.0)
        assert len(flows) == 2

    def test_bidirectional_same_flow(self):
        base = time.time()
        pkts = [
            _make_packet(src="1.1.1.1", dst="2.2.2.2", sport=1234, dport=80, ts=base),
            _make_packet(src="2.2.2.2", dst="1.1.1.1", sport=80, dport=1234, ts=base+1),
        ]
        flows = aggregate_flows(pkts)
        assert len(flows) == 1
        assert flows[0].total_packets == 2

    def test_stats_computed(self):
        base = time.time()
        pkts = [_make_packet(ts=base + i, length=200) for i in range(10)]
        flow = aggregate_flows(pkts)[0]
        assert flow.total_bytes == 2000
        assert flow.avg_packet_size == 200.0
        assert flow.duration > 0


class TestFeatureExtractor:
    def _records(self, n=10):
        base = time.time()
        pkts = [_make_packet(ts=base + i) for i in range(n)]
        flows = aggregate_flows(pkts)
        return flows_to_records(flows)

    def test_engineer_adds_columns(self):
        import pandas as pd
        recs = self._records()
        df = engineer_features(recs)
        assert "syn_ratio" in df.columns
        assert "log_bytes" in df.columns
        assert "rst_ratio" in df.columns

    def test_feature_matrix_shape(self):
        recs = self._records(20)
        import pandas as pd
        df = engineer_features(recs)
        X = build_feature_matrix(df)
        assert X.ndim == 2
        assert X.shape[0] == len(recs)


class TestAnomalyDetector:
    def _make_records(self, n=50):
        base = time.time()
        pkts = []
        for i in range(n):
            pkts.append(_make_packet(
                src=f"10.0.{i%5}.{i%254+1}",
                ts=base + i * 0.1,
                length=100 + (i % 50),
            ))
        flows = aggregate_flows(pkts)
        return flows_to_records(flows)

    def test_fit_score(self):
        import numpy as np
        recs = self._make_records(60)
        det = AnomalyDetector(contamination=0.1)
        det.fit(recs)
        scores = det.score(recs)
        assert scores.shape[0] == len(recs)
        assert 0.0 <= scores.min() <= scores.max() <= 1.0

    def test_label(self):
        recs = self._make_records(60)
        det = AnomalyDetector(contamination=0.1)
        det.fit(recs)
        labeled = det.label(recs, threshold=0.5)
        assert all("anomaly_score" in r for r in labeled)
        assert all(r["anomaly_label"] in ("ANOMALOUS", "NORMAL") for r in labeled)


class TestDetectionRules:
    def _flow(self, **kwargs):
        base = {
            "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2",
            "src_port": 12345, "dst_port": 80, "protocol": "TCP",
            "total_packets": 100, "total_bytes": 10000,
            "packets_per_second": 10.0, "bytes_per_second": 1000.0,
            "syn_ratio": 0.0, "ack_ratio": 0.9, "rst_ratio": 0.0,
            "fin_ratio": 0.0, "avg_packet_size": 100.0,
            "duration": 10.0, "payload_ratio": 0.8,
        }
        base.update(kwargs)
        return base

    def test_port_scan_detected(self):
        flow = self._flow(syn_ratio=0.85, ack_ratio=0.1, total_packets=50)
        alerts = apply_rules([flow])
        assert any(a.rule_name == "port_scan" for a in alerts)

    def test_syn_flood_detected(self):
        flow = self._flow(packets_per_second=600, syn_ratio=0.9)
        alerts = apply_rules([flow])
        assert any(a.rule_name == "syn_flood" for a in alerts)

    def test_dns_tunnel_detected(self):
        flow = self._flow(dst_port=53, avg_packet_size=500, bytes_per_second=10000)
        alerts = apply_rules([flow])
        assert any(a.rule_name == "dns_tunnelling" for a in alerts)

    def test_exfil_detected(self):
        flow = self._flow(total_bytes=100_000_000, dst_port=4444)
        alerts = apply_rules([flow])
        assert any(a.rule_name == "data_exfiltration" for a in alerts)

    def test_normal_flow_no_alert(self):
        flow = self._flow()
        alerts = apply_rules([flow])
        assert len(alerts) == 0

    def test_brute_force_ssh(self):
        flow = self._flow(dst_port=22, rst_ratio=0.5, total_packets=20)
        alerts = apply_rules([flow])
        assert any(a.rule_name == "brute_force" for a in alerts)
