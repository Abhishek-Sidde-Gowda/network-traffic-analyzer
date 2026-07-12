"""
Convert raw flow records into the ML feature matrix used by anomaly detectors.
"""
from __future__ import annotations

import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler

NUMERIC_FEATURES = [
    "duration",
    "total_bytes",
    "total_packets",
    "avg_packet_size",
    "bytes_per_second",
    "packets_per_second",
    "syn_count",
    "fin_count",
    "rst_count",
    "psh_count",
    "ack_count",
    "unique_ttls",
    "payload_ratio",
    "syn_ratio",          # syn / total_packets
    "rst_ratio",          # rst / total_packets
    "fin_ratio",
    "ack_ratio",
    "log_bytes",          # log1p(total_bytes)
    "log_packets",
    "log_bps",
]

PROTO_ENCODING = {"TCP": 0, "UDP": 1, "ICMP": 2, "ICMPv6": 3, "OTHER": 4}


def engineer_features(records: list[dict]) -> pd.DataFrame:
    df = pd.DataFrame(records)
    if df.empty:
        return df

    # Guard division
    tp = df["total_packets"].clip(lower=1)
    tb = df["total_bytes"].clip(lower=1)

    df["syn_ratio"] = df["syn_count"] / tp
    df["rst_ratio"] = df["rst_count"] / tp
    df["fin_ratio"] = df["fin_count"] / tp
    df["ack_ratio"] = df["ack_count"] / tp
    df["log_bytes"] = np.log1p(df["total_bytes"])
    df["log_packets"] = np.log1p(df["total_packets"])
    df["log_bps"] = np.log1p(df["bytes_per_second"])
    df["proto_enc"] = df["protocol"].map(PROTO_ENCODING).fillna(4).astype(int)

    return df


def build_feature_matrix(df: pd.DataFrame) -> np.ndarray:
    """Return ndarray of shape (n_flows, n_features) for ML models."""
    cols = [c for c in NUMERIC_FEATURES if c in df.columns]
    X = df[cols].fillna(0).values.astype(np.float32)
    return X


class FlowScaler:
    """Thin wrapper around StandardScaler that persists feature names."""

    def __init__(self):
        self._scaler = StandardScaler()
        self.feature_names: list[str] = []

    def fit_transform(self, df: pd.DataFrame) -> np.ndarray:
        X = build_feature_matrix(df)
        self.feature_names = [c for c in NUMERIC_FEATURES if c in df.columns]
        return self._scaler.fit_transform(X)

    def transform(self, df: pd.DataFrame) -> np.ndarray:
        X = build_feature_matrix(df)
        return self._scaler.transform(X)
