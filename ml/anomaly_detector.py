"""
Ensemble anomaly detector: IsolationForest + DBSCAN outlier labelling + LOF.
Scores are normalised to [0, 1] where 1 = most anomalous.
"""
from __future__ import annotations

import os
import joblib
import numpy as np
import pandas as pd
from pathlib import Path
from sklearn.ensemble import IsolationForest
from sklearn.neighbors import LocalOutlierFactor
from sklearn.preprocessing import MinMaxScaler

from .feature_extractor import FlowScaler, engineer_features, build_feature_matrix

MODEL_DIR = Path(__file__).parent / "saved_models"
MODEL_PATH = MODEL_DIR / "isolation_forest.joblib"
SCALER_PATH = MODEL_DIR / "scaler.joblib"


class AnomalyDetector:
    """
    Trains on baseline traffic (assumed normal) then scores new flows.
    Uses IsolationForest as the primary model and LOF as a second opinion.
    The final anomaly score is a weighted average.
    """

    def __init__(
        self,
        contamination: float = 0.05,
        n_estimators: int = 200,
        random_state: int = 42,
    ):
        self.contamination = contamination
        self._if = IsolationForest(
            n_estimators=n_estimators,
            contamination=contamination,
            random_state=random_state,
            n_jobs=-1,
        )
        self._scaler = FlowScaler()
        self._fitted = False

    # ------------------------------------------------------------------
    # Training
    # ------------------------------------------------------------------

    def fit(self, records: list[dict]) -> "AnomalyDetector":
        df = engineer_features(records)
        X = self._scaler.fit_transform(df)
        self._if.fit(X)
        self._fitted = True
        return self

    # ------------------------------------------------------------------
    # Scoring
    # ------------------------------------------------------------------

    def score(self, records: list[dict]) -> np.ndarray:
        """Return anomaly score array in [0, 1] for each flow record."""
        if not self._fitted:
            raise RuntimeError("Call fit() or load() before score().")
        df = engineer_features(records)
        X = self._scaler.transform(df)

        # IsolationForest: negative_outlier_factor → lower = more anomalous
        if_raw = -self._if.score_samples(X)          # flip so higher = more anomalous

        # LOF in novelty=False mode (fit per batch — lightweight second opinion)
        lof = LocalOutlierFactor(n_neighbors=min(20, len(X)), novelty=False)
        lof_raw = -lof.fit_predict(X).astype(float)   # -1 inlier, 1 outlier → scale
        lof_scores = (lof_raw + 1) / 2                # 0 = inlier, 1 = outlier

        # Normalize IF scores
        scaler = MinMaxScaler()
        if_scores = scaler.fit_transform(if_raw.reshape(-1, 1)).ravel()

        # Weighted ensemble
        final = 0.7 * if_scores + 0.3 * lof_scores
        return np.clip(final, 0, 1)

    def label(self, records: list[dict], threshold: float = 0.6) -> list[dict]:
        """
        Returns records enriched with 'anomaly_score' and 'anomaly_label'.
        threshold: score above which a flow is flagged ANOMALOUS.
        """
        scores = self.score(records)
        enriched = []
        for rec, score in zip(records, scores):
            rec = dict(rec)
            rec["anomaly_score"] = round(float(score), 4)
            rec["anomaly_label"] = "ANOMALOUS" if score >= threshold else "NORMAL"
            enriched.append(rec)
        return enriched

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def save(self, model_dir: Path = MODEL_DIR) -> None:
        model_dir.mkdir(parents=True, exist_ok=True)
        joblib.dump(self._if, model_dir / "isolation_forest.joblib")
        joblib.dump(self._scaler, model_dir / "scaler.joblib")

    @classmethod
    def load(cls, model_dir: Path = MODEL_DIR) -> "AnomalyDetector":
        det = cls.__new__(cls)
        det._if = joblib.load(model_dir / "isolation_forest.joblib")
        det._scaler = joblib.load(model_dir / "scaler.joblib")
        det.contamination = det._if.contamination
        det._fitted = True
        return det
