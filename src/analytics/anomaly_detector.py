"""Anomaly detection using Isolation Forest for security incidents."""

import logging
import pickle
import time
from typing import Any, Dict, List, Optional, Tuple

import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

logger = logging.getLogger(__name__)


class AnomalyDetector:
    """Isolation Forest-based anomaly detection for incidents."""

    def __init__(
        self, contamination: float = 0.1, n_estimators: int = 100, random_state: int = 42
    ) -> None:
        """Initialize anomaly detector.

        Args:
            contamination: Expected proportion of anomalies (default: 10%)
            n_estimators: Number of isolation trees
            random_state: Random seed for reproducibility
        """
        self.model = IsolationForest(
            contamination=contamination,
            n_estimators=n_estimators,
            max_samples="auto",
            random_state=random_state,
            n_jobs=-1,
        )
        self.scaler = StandardScaler()
        self.is_trained = False
        self.feature_names = ["severity_score", "affected_users_count", "time_of_day", "cve_score"]

    def _prepare_features(self, incidents: List[Dict[str, Any]]) -> pd.DataFrame:
        """Prepare incident features for anomaly detection.

        Input features:
            - severity_score: 1-5 scale
            - affected_users_count: Number of affected users
            - detected_at: Timestamp (converted to time_of_day)
            - cve_score: CVE score if available (0-10)

        Args:
            incidents: List of incident dictionaries

        Returns:
            DataFrame with normalized features
        """
        df = pd.DataFrame(incidents)

        # Extract time of day (0-23 hours)
        if "detected_at" in df.columns:
            df["detected_at"] = pd.to_datetime(df["detected_at"])
            df["time_of_day"] = df["detected_at"].dt.hour
        else:
            df["time_of_day"] = 12  # Default midday

        # Fill missing CVE scores
        if "cve_score" not in df.columns:
            df["cve_score"] = 0.0
        df["cve_score"] = df["cve_score"].fillna(0.0)

        # Select features
        feature_df = df[self.feature_names].copy()

        return feature_df

    def train(self, normal_incidents: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Train anomaly detector on normal incidents.

        Args:
            normal_incidents: Historical incidents representing normal behavior

        Returns:
            Training statistics
        """
        start_time = time.perf_counter()

        # Prepare features
        X = self._prepare_features(normal_incidents)

        # Fit scaler
        X_scaled = self.scaler.fit_transform(X)

        # Train model
        self.model.fit(X_scaled)
        self.is_trained = True

        # Get training anomalies for reporting
        predictions = self.model.predict(X_scaled)
        anomaly_count = (predictions == -1).sum()

        duration = (time.perf_counter() - start_time) * 1000

        stats = {
            "training_samples": len(normal_incidents),
            "detected_anomalies": int(anomaly_count),
            "anomaly_rate": float(anomaly_count / len(normal_incidents)),
            "training_time_ms": duration,
        }

        logger.info(
            "Anomaly detector trained: samples=%d, anomalies=%d, duration=%.2fms",
            len(normal_incidents),
            anomaly_count,
            duration,
        )

        return stats

    def _explain_anomaly(
        self, features: Dict[str, float], anomaly_score: float
    ) -> Tuple[str, List[str]]:
        """Explain why an incident is anomalous.

        Args:
            features: Feature values
            anomaly_score: Anomaly score (0-1)

        Returns:
            Tuple of (anomaly_type, top_3_contributing_features)
        """
        # Determine anomaly type based on features
        severity = features.get("severity_score", 0)
        affected_users = features.get("affected_users_count", 0)
        cve = features.get("cve_score", 0)
        time_of_day = features.get("time_of_day", 12)

        reasons = []

        # Check severity
        if severity >= 4:
            reasons.append(f"High severity (level {severity})")

        # Check affected users
        if affected_users > 1000:
            reasons.append(f"Large user impact ({affected_users} users)")
        elif affected_users > 500:
            reasons.append(f"Significant user impact ({affected_users} users)")

        # Check CVE score
        if cve >= 9.0:
            reasons.append(f"Critical CVE score ({cve:.1f})")
        elif cve >= 7.0:
            reasons.append(f"High CVE score ({cve:.1f})")

        # Check time of day (unusual hours)
        if time_of_day < 6 or time_of_day > 22:
            reasons.append(f"Unusual time ({time_of_day}:00)")

        # Determine anomaly type
        if anomaly_score > 0.8:
            anomaly_type = "critical"
        elif anomaly_score > 0.6:
            anomaly_type = "high"
        elif anomaly_score > 0.4:
            anomaly_type = "medium"
        else:
            anomaly_type = "low"

        # Return top 3 reasons
        return anomaly_type, reasons[:3] if reasons else ["Statistical outlier"]

    async def detect(self, incidents: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detect anomalies in incidents.

        Args:
            incidents: List of incidents to analyze

        Returns:
            List of anomaly results with scores and explanations

        Performance: <200ms for 1K incidents
        """
        start_time = time.perf_counter()

        if not self.is_trained:
            raise ValueError("Model not trained. Call train() first.")

        # Prepare features
        X = self._prepare_features(incidents)
        X_scaled = self.scaler.transform(X)

        # Predict anomalies
        predictions = self.model.predict(X_scaled)  # -1 for anomaly, 1 for normal

        # Get anomaly scores (lower = more anomalous)
        scores = self.model.score_samples(X_scaled)

        # Normalize scores to 0-1 (higher = more anomalous)
        min_score = scores.min()
        max_score = scores.max()
        normalized_scores = 1 - (scores - min_score) / (max_score - min_score + 1e-10)

        # Build results
        results = []

        for i, (incident, prediction, score) in enumerate(
            zip(incidents, predictions, normalized_scores)
        ):
            is_anomaly = prediction == -1

            # Get feature values for explanation
            features = {name: float(X.iloc[i][name]) for name in self.feature_names}

            # Explain anomaly
            anomaly_type, reasons = self._explain_anomaly(features, score)

            result = {
                "incident_id": incident.get("id", f"incident_{i}"),
                "is_anomaly": bool(is_anomaly),
                "anomaly_score": float(score),
                "anomaly_type": anomaly_type if is_anomaly else "normal",
                "anomaly_reason": "; ".join(reasons) if is_anomaly else "Within normal range",
                "contributing_features": reasons if is_anomaly else [],
                "features": features,
            }

            results.append(result)

        duration = (time.perf_counter() - start_time) * 1000

        anomaly_count = sum(1 for r in results if r["is_anomaly"])

        logger.info(
            "Anomaly detection: incidents=%d, anomalies=%d, duration=%.2fms",
            len(incidents),
            anomaly_count,
            duration,
        )

        # Verify performance target (<200ms for 1K incidents)
        if len(incidents) >= 1000 and duration > 200:
            logger.warning(
                "Anomaly detection exceeded 200ms target for 1K incidents: %.2fms", duration
            )

        return results

    async def detect_single(self, incident: Dict[str, Any]) -> Dict[str, Any]:
        """Detect anomaly for a single incident.

        Args:
            incident: Single incident to analyze

        Returns:
            Anomaly result with score and explanation
        """
        results = await self.detect([incident])
        return results[0]

    def save_model(self, filepath: str) -> None:
        """Save trained model to disk."""
        if not self.is_trained:
            raise ValueError("Cannot save untrained model")

        with open(filepath, "wb") as f:
            pickle.dump(
                {"model": self.model, "scaler": self.scaler, "feature_names": self.feature_names}, f
            )

        logger.info("Anomaly detector saved to %s", filepath)

    def load_model(self, filepath: str) -> None:
        """Load trained model from disk."""
        with open(filepath, "rb") as f:
            data = pickle.load(f)

        self.model = data["model"]
        self.scaler = data["scaler"]
        self.feature_names = data["feature_names"]
        self.is_trained = True

        logger.info("Anomaly detector loaded from %s", filepath)


# Global detector instance
_detector: Optional[AnomalyDetector] = None


def get_anomaly_detector() -> AnomalyDetector:
    """Get or create global anomaly detector instance."""
    global _detector
    if _detector is None:
        _detector = AnomalyDetector()
    return _detector
