"""Isolation Forest-based anomaly detection for security events."""
from typing import Any, Dict, List, Optional

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler


class AnomalyDetector:
    """Anomaly detection using Isolation Forest algorithm.

    Detects anomalies in security metrics and events using unsupervised learning.
    Provides anomaly scoring and real-time detection capabilities.

    Attributes:
        model: IsolationForest model instance
        scaler: StandardScaler for feature normalization
        feature_names: List of feature column names
        trained: Flag indicating if model is trained
        contamination: Expected proportion of anomalies
    """

    def __init__(
        self,
        contamination: float = 0.1,
        n_estimators: int = 100,
        random_state: int = 42
    ) -> None:
        """Initialize the anomaly detector.

        Args:
            contamination: Expected proportion of outliers (0-0.5)
            n_estimators: Number of base estimators in the ensemble
            random_state: Random state for reproducibility
        """
        self.model = IsolationForest(
            contamination=contamination,
            n_estimators=n_estimators,
            random_state=random_state,
            n_jobs=-1
        )
        self.scaler = StandardScaler()
        self.feature_names: Optional[List[str]] = None
        self.trained = False
        self.contamination = contamination

    async def train(
        self,
        features: pd.DataFrame,
        feature_columns: Optional[List[str]] = None
    ) -> None:
        """Train the anomaly detection model on historical data.

        Args:
            features: DataFrame containing feature data
            feature_columns: List of columns to use as features. If None, uses all numeric columns

        Raises:
            ValueError: If features DataFrame is empty
        """
        if features.empty:
            raise ValueError("Features DataFrame cannot be empty")

        if feature_columns is None:
            feature_columns = features.select_dtypes(include=[np.number]).columns.tolist()

        self.feature_names = feature_columns
        X = features[feature_columns].values

        X_scaled = self.scaler.fit_transform(X)

        self.model.fit(X_scaled)
        self.trained = True

    async def detect(
        self,
        features: pd.DataFrame
    ) -> Dict[str, Any]:
        """Detect anomalies in new data.

        Args:
            features: DataFrame containing feature data to analyze

        Returns:
            Dictionary containing:
                - predictions: Array of predictions (-1 for anomaly, 1 for normal)
                - scores: Anomaly scores (lower = more anomalous)
                - is_anomaly: Boolean array indicating anomalies
                - anomaly_indices: Indices of detected anomalies

        Raises:
            RuntimeError: If model not trained
            ValueError: If features missing required columns
        """
        if not self.trained:
            raise RuntimeError("Model must be trained before detection")

        if self.feature_names is None:
            raise RuntimeError("Feature names not set")

        missing_cols = set(self.feature_names) - set(features.columns)
        if missing_cols:
            raise ValueError(f"Missing required columns: {missing_cols}")

        X = features[self.feature_names].values
        X_scaled = self.scaler.transform(X)

        predictions = self.model.predict(X_scaled)
        scores = self.model.score_samples(X_scaled)

        is_anomaly = predictions == -1
        anomaly_indices = np.where(is_anomaly)[0].tolist()

        return {
            'predictions': predictions.tolist(),
            'scores': scores.tolist(),
            'is_anomaly': is_anomaly.tolist(),
            'anomaly_indices': anomaly_indices
        }

    async def get_anomaly_score(
        self,
        features: Dict[str, float]
    ) -> float:
        """Calculate anomaly score for a single data point.

        Args:
            features: Dictionary of feature name to value

        Returns:
            Anomaly score (lower = more anomalous, typically in range [-0.5, 0.5])

        Raises:
            RuntimeError: If model not trained
            ValueError: If features missing required columns
        """
        if not self.trained or self.feature_names is None:
            raise RuntimeError("Model must be trained before scoring")

        missing_features = set(self.feature_names) - set(features.keys())
        if missing_features:
            raise ValueError(f"Missing required features: {missing_features}")

        X = np.array([[features[col] for col in self.feature_names]])
        X_scaled = self.scaler.transform(X)

        score = self.model.score_samples(X_scaled)[0]
        return float(score)

    async def detect_realtime(
        self,
        features: Dict[str, float],
        threshold: Optional[float] = None
    ) -> Dict[str, Any]:
        """Real-time anomaly detection for a single event.

        Args:
            features: Dictionary of feature name to value
            threshold: Custom anomaly threshold. If None, uses model default

        Returns:
            Dictionary containing:
                - is_anomaly: Boolean indicating if event is anomalous
                - score: Anomaly score
                - severity: Severity level (1-5)
                - confidence: Detection confidence (0-1)
        """
        score = await self.get_anomaly_score(features)

        if threshold is None:
            is_anomaly = score < -0.1
        else:
            is_anomaly = score < threshold

        severity = await self._calculate_severity(score)
        confidence = await self._calculate_confidence(score)

        return {
            'is_anomaly': is_anomaly,
            'score': float(score),
            'severity': severity,
            'confidence': confidence
        }

    async def _calculate_severity(self, score: float) -> int:
        """Calculate severity level from anomaly score.

        Args:
            score: Anomaly score

        Returns:
            Severity level (1-5, where 5 is most severe)
        """
        if score >= 0:
            return 1
        elif score >= -0.1:
            return 2
        elif score >= -0.2:
            return 3
        elif score >= -0.3:
            return 4
        else:
            return 5

    async def _calculate_confidence(self, score: float) -> float:
        """Calculate detection confidence from anomaly score.

        Args:
            score: Anomaly score

        Returns:
            Confidence value (0-1)
        """
        confidence = 1.0 - (1.0 / (1.0 + abs(score) * 10))
        return float(np.clip(confidence, 0.0, 1.0))

    async def explain_anomaly(
        self,
        features: Dict[str, float],
        top_n: int = 5
    ) -> List[Dict[str, Any]]:
        """Explain which features contributed most to anomaly detection.

        Args:
            features: Dictionary of feature name to value
            top_n: Number of top contributing features to return

        Returns:
            List of dictionaries with feature contributions, sorted by importance
        """
        if not self.trained or self.feature_names is None:
            raise RuntimeError("Model must be trained before explanation")

        feature_values = [features[col] for col in self.feature_names]
        scaled_values = self.scaler.transform([feature_values])[0]

        mean_values = self.scaler.mean_
        std_values = self.scaler.scale_

        contributions = []
        for i, feature_name in enumerate(self.feature_names):
            z_score = abs((feature_values[i] - mean_values[i]) / std_values[i])
            contributions.append({
                'feature': feature_name,
                'value': float(feature_values[i]),
                'z_score': float(z_score),
                'contribution': float(z_score)
            })

        contributions.sort(key=lambda x: x['contribution'], reverse=True)
        return contributions[:top_n]

    async def get_statistics(self) -> Dict[str, Any]:
        """Get model statistics and metadata.

        Returns:
            Dictionary with model statistics

        Raises:
            RuntimeError: If model not trained
        """
        if not self.trained:
            raise RuntimeError("Model must be trained first")

        return {
            'trained': self.trained,
            'n_estimators': self.model.n_estimators,
            'contamination': self.contamination,
            'n_features': len(self.feature_names) if self.feature_names else 0,
            'feature_names': self.feature_names or []
        }
