"""
Anomaly detection engine for Security Data Fabric.
Implements Z-score baseline analysis and Isolation Forest for multi-metric anomaly detection.
"""
import logging
from datetime import datetime, timedelta
from enum import Enum
from typing import Dict, List, Optional, Tuple
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

from src.config.settings import settings

logger = logging.getLogger(__name__)


class AnomalyLevel(str, Enum):
    """Anomaly severity levels."""
    NORMAL = "normal"
    WARNING = "warning"
    CRITICAL = "critical"
    EXTREME = "extreme"


class AnomalyDetector:
    """
    Anomaly detection engine with multiple detection methods.
    
    Supports:
    - Z-score baseline analysis with sliding window
    - Isolation Forest for multivariate anomaly detection
    - Multi-metric support
    - Configurable thresholds
    """
    
    def __init__(
        self,
        window_size: int = 50,
        z_threshold: Optional[float] = None,
        contamination: float = 0.1
    ):
        """
        Initialize anomaly detector.
        
        Args:
            window_size: Number of data points for sliding window baseline
            z_threshold: Z-score threshold (uses ml_anomaly_threshold from settings if None)
            contamination: Expected proportion of outliers for Isolation Forest
        """
        self.window_size = window_size
        self.z_threshold = z_threshold or settings.ml_anomaly_threshold
        self.contamination = contamination
        self.baseline_stats: Dict[str, Dict[str, float]] = {}
        self.isolation_forest: Optional[IsolationForest] = None
        
        logger.info(
            f"AnomalyDetector initialized: window={window_size}, "
            f"z_threshold={self.z_threshold}, contamination={contamination}"
        )
    
    def detect_zscore(
        self,
        metric_name: str,
        value: float,
        historical_values: Optional[List[float]] = None
    ) -> Tuple[AnomalyLevel, float, str]:
        """
        Detect anomalies using Z-score analysis.
        
        Args:
            metric_name: Name of the metric
            value: Current metric value
            historical_values: Historical values for baseline (uses stored baseline if None)
        
        Returns:
            Tuple of (anomaly_level, confidence_score, explanation)
        """
        try:
            # Update baseline if historical values provided
            if historical_values is not None and len(historical_values) > 0:
                self._update_baseline(metric_name, historical_values)
            
            # Check if we have baseline statistics
            if metric_name not in self.baseline_stats:
                logger.warning(f"No baseline for metric '{metric_name}', cannot detect anomaly")
                return AnomalyLevel.NORMAL, 0.0, "Insufficient baseline data"
            
            stats = self.baseline_stats[metric_name]
            mean = stats["mean"]
            std = stats["std"]
            
            # Handle zero standard deviation
            if std == 0:
                if abs(value - mean) > 0.001:  # Allow for floating point precision
                    return (
                        AnomalyLevel.EXTREME,
                        1.0,
                        f"Value {value:.2f} deviates from constant baseline {mean:.2f}"
                    )
                return AnomalyLevel.NORMAL, 1.0, f"Value matches baseline {mean:.2f}"
            
            # Calculate Z-score
            z_score = abs((value - mean) / std)
            
            # Determine anomaly level based on Z-score
            if z_score < self.z_threshold:
                level = AnomalyLevel.NORMAL
            elif z_score < self.z_threshold * 1.5:
                level = AnomalyLevel.WARNING
            elif z_score < self.z_threshold * 2:
                level = AnomalyLevel.CRITICAL
            else:
                level = AnomalyLevel.EXTREME
            
            # Calculate confidence score (0-1)
            confidence = min(z_score / (self.z_threshold * 2), 1.0)
            
            # Generate explanation
            explanation = self._generate_explanation(
                metric_name, value, mean, std, z_score, level
            )
            
            logger.debug(
                f"Z-score detection for {metric_name}: value={value:.2f}, "
                f"z_score={z_score:.2f}, level={level}, confidence={confidence:.2f}"
            )
            
            return level, confidence, explanation
            
        except Exception as e:
            logger.error(f"Error in Z-score detection for {metric_name}: {e}")
            return AnomalyLevel.NORMAL, 0.0, f"Detection error: {str(e)}"
    
    def detect_multivariate(
        self,
        metrics: Dict[str, float],
        training_data: Optional[pd.DataFrame] = None
    ) -> Tuple[AnomalyLevel, float, str]:
        """
        Detect anomalies using Isolation Forest for multivariate analysis.
        
        Args:
            metrics: Dictionary of metric name to value
            training_data: DataFrame with historical metrics (trains new model if provided)
        
        Returns:
            Tuple of (anomaly_level, confidence_score, explanation)
        """
        try:
            # Train new model if training data provided
            if training_data is not None:
                self._train_isolation_forest(training_data)
            
            # Check if model is trained
            if self.isolation_forest is None:
                logger.warning("Isolation Forest not trained, cannot detect multivariate anomalies")
                return AnomalyLevel.NORMAL, 0.0, "Model not trained"
            
            # Prepare data for prediction
            metric_names = sorted(metrics.keys())
            values = np.array([[metrics[name] for name in metric_names]])
            
            # Predict anomaly score
            # Returns -1 for anomalies, 1 for normal
            prediction = self.isolation_forest.predict(values)[0]
            
            # Get anomaly score (lower is more anomalous)
            anomaly_score = self.isolation_forest.score_samples(values)[0]
            
            # Convert score to confidence (invert and normalize)
            # Anomaly scores typically range from -0.5 to 0.5
            confidence = max(0.0, min(1.0, (-anomaly_score + 0.5) / 1.0))
            
            # Determine level
            if prediction == 1:
                level = AnomalyLevel.NORMAL
            else:
                if confidence > 0.8:
                    level = AnomalyLevel.EXTREME
                elif confidence > 0.7:
                    level = AnomalyLevel.CRITICAL
                else:
                    level = AnomalyLevel.WARNING
            
            # Generate explanation
            explanation = self._generate_multivariate_explanation(
                metrics, level, confidence, anomaly_score
            )
            
            logger.debug(
                f"Multivariate detection: prediction={prediction}, "
                f"score={anomaly_score:.4f}, level={level}, confidence={confidence:.2f}"
            )
            
            return level, confidence, explanation
            
        except Exception as e:
            logger.error(f"Error in multivariate detection: {e}")
            return AnomalyLevel.NORMAL, 0.0, f"Detection error: {str(e)}"
    
    def _update_baseline(self, metric_name: str, values: List[float]) -> None:
        """Update baseline statistics for a metric."""
        if len(values) == 0:
            return
        
        # Use sliding window
        window_values = values[-self.window_size:]
        
        self.baseline_stats[metric_name] = {
            "mean": float(np.mean(window_values)),
            "std": float(np.std(window_values)),
            "min": float(np.min(window_values)),
            "max": float(np.max(window_values)),
            "count": len(window_values)
        }
        
        logger.debug(f"Updated baseline for {metric_name}: {self.baseline_stats[metric_name]}")
    
    def _train_isolation_forest(self, training_data: pd.DataFrame) -> None:
        """Train Isolation Forest on historical data."""
        if training_data.empty:
            logger.warning("Empty training data, cannot train Isolation Forest")
            return
        
        self.isolation_forest = IsolationForest(
            contamination=self.contamination,
            random_state=42,
            n_estimators=100
        )
        self.isolation_forest.fit(training_data)
        
        logger.info(f"Trained Isolation Forest on {len(training_data)} samples")
    
    def _generate_explanation(
        self,
        metric_name: str,
        value: float,
        mean: float,
        std: float,
        z_score: float,
        level: AnomalyLevel
    ) -> str:
        """Generate human-readable explanation for Z-score anomaly."""
        if level == AnomalyLevel.NORMAL:
            return (
                f"{metric_name}={value:.2f} is within normal range "
                f"(baseline: {mean:.2f}±{std:.2f})"
            )
        
        deviation = abs(value - mean)
        direction = "above" if value > mean else "below"
        
        return (
            f"{metric_name}={value:.2f} is {deviation:.2f} ({z_score:.1f}σ) "
            f"{direction} baseline {mean:.2f}±{std:.2f} - {level.value} anomaly detected"
        )
    
    def _generate_multivariate_explanation(
        self,
        metrics: Dict[str, float],
        level: AnomalyLevel,
        confidence: float,
        anomaly_score: float
    ) -> str:
        """Generate human-readable explanation for multivariate anomaly."""
        if level == AnomalyLevel.NORMAL:
            return f"Multivariate pattern is normal (score: {anomaly_score:.4f})"
        
        metric_summary = ", ".join([f"{k}={v:.2f}" for k, v in list(metrics.items())[:3]])
        if len(metrics) > 3:
            metric_summary += f" (+{len(metrics)-3} more)"
        
        return (
            f"Abnormal multivariate pattern detected ({level.value}): "
            f"{metric_summary} - confidence: {confidence:.2%}, score: {anomaly_score:.4f}"
        )
    
    def get_baseline_stats(self, metric_name: str) -> Optional[Dict[str, float]]:
        """Get baseline statistics for a metric."""
        return self.baseline_stats.get(metric_name)
    
    def clear_baseline(self, metric_name: Optional[str] = None) -> None:
        """Clear baseline statistics."""
        if metric_name:
            self.baseline_stats.pop(metric_name, None)
            logger.info(f"Cleared baseline for {metric_name}")
        else:
            self.baseline_stats.clear()
            logger.info("Cleared all baselines")
