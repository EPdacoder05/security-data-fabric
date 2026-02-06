"""Anomaly detection for security metrics and events."""
import numpy as np
import pandas as pd
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any
from sklearn.ensemble import IsolationForest

from src.config import settings
from src.observability.logging import get_logger
from src.observability.metrics import metrics

logger = get_logger(__name__)


class AnomalyDetector:
    """Detects anomalies in security metrics using statistical and ML methods."""

    def __init__(
        self,
        window_hours: int = 24,
        contamination: float = 0.1,
    ) -> None:
        """Initialize anomaly detector.

        Args:
            window_hours: Sliding window size for baseline calculation
            contamination: Expected proportion of anomalies for Isolation Forest
        """
        self.window_hours = window_hours
        self.contamination = contamination
        self.baseline_cache: Dict[str, pd.DataFrame] = {}
        self.isolation_forest: Optional[IsolationForest] = None
        
        logger.info(
            "Initialized AnomalyDetector",
            extra={
                "window_hours": window_hours,
                "contamination": contamination,
            },
        )

    def detect_zscore_anomaly(
        self,
        metric_name: str,
        current_value: float,
        historical_data: List[Tuple[datetime, float]],
    ) -> Dict[str, Any]:
        """Detect anomaly using Z-score method with sliding window baseline.

        Args:
            metric_name: Name of the metric
            current_value: Current metric value
            historical_data: List of (timestamp, value) tuples for baseline

        Returns:
            Dictionary with anomaly detection results
        """
        metrics.increment("anomaly_detector.zscore_checks")
        
        try:
            if len(historical_data) < 10:
                logger.warning(
                    "Insufficient data for anomaly detection",
                    extra={"metric": metric_name, "data_points": len(historical_data)},
                )
                return {
                    "is_anomaly": False,
                    "severity": "info",
                    "z_score": 0.0,
                    "explanation": "Insufficient historical data for analysis",
                }

            # Convert to DataFrame and filter to window
            df = pd.DataFrame(historical_data, columns=["timestamp", "value"])
            cutoff_time = datetime.utcnow() - timedelta(hours=self.window_hours)
            df = df[df["timestamp"] >= cutoff_time]

            if len(df) < 10:
                return {
                    "is_anomaly": False,
                    "severity": "info",
                    "z_score": 0.0,
                    "explanation": "Insufficient data in time window",
                }

            # Calculate baseline statistics
            baseline_mean = df["value"].mean()
            baseline_std = df["value"].std()

            if baseline_std == 0:
                z_score = 0.0
            else:
                z_score = abs((current_value - baseline_mean) / baseline_std)

            # Determine severity based on configurable thresholds
            is_anomaly = z_score >= settings.anomaly_warning_threshold
            
            if z_score >= settings.anomaly_extreme_threshold:
                severity = "extreme"
            elif z_score >= settings.anomaly_critical_threshold:
                severity = "critical"
            elif z_score >= settings.anomaly_warning_threshold:
                severity = "warning"
            else:
                severity = "normal"

            # Generate human-readable explanation
            direction = "above" if current_value > baseline_mean else "below"
            explanation = (
                f"{metric_name} value {current_value:.2f} is {z_score:.2f} "
                f"standard deviations {direction} the {self.window_hours}h baseline "
                f"mean of {baseline_mean:.2f} (std: {baseline_std:.2f})"
            )

            if is_anomaly:
                metrics.increment("anomaly_detector.anomalies_detected")
                logger.info(
                    "Anomaly detected",
                    extra={
                        "metric": metric_name,
                        "z_score": z_score,
                        "severity": severity,
                    },
                )

            return {
                "is_anomaly": is_anomaly,
                "severity": severity,
                "z_score": round(z_score, 3),
                "baseline_mean": round(baseline_mean, 3),
                "baseline_std": round(baseline_std, 3),
                "current_value": round(current_value, 3),
                "deviation_percent": round(
                    ((current_value - baseline_mean) / baseline_mean * 100)
                    if baseline_mean != 0
                    else 0.0,
                    2,
                ),
                "explanation": explanation,
            }

        except Exception as e:
            logger.error(
                "Error in Z-score anomaly detection",
                extra={"metric": metric_name, "error": str(e)},
                exc_info=True,
            )
            metrics.increment("anomaly_detector.errors")
            return {
                "is_anomaly": False,
                "severity": "error",
                "z_score": 0.0,
                "explanation": f"Error during analysis: {str(e)}",
            }

    def detect_multivariate_anomaly(
        self,
        metrics_data: Dict[str, List[Tuple[datetime, float]]],
        current_values: Dict[str, float],
    ) -> Dict[str, Any]:
        """Detect multivariate anomalies using Isolation Forest.

        Args:
            metrics_data: Dictionary mapping metric names to historical data
            current_values: Current values for each metric

        Returns:
            Dictionary with multivariate anomaly detection results
        """
        metrics.increment("anomaly_detector.multivariate_checks")
        
        try:
            # Validate input
            if not metrics_data or not current_values:
                return {
                    "is_anomaly": False,
                    "severity": "info",
                    "anomaly_score": 0.0,
                    "explanation": "No metrics provided",
                }

            # Align all metrics to common time points
            all_timestamps = set()
            for data in metrics_data.values():
                all_timestamps.update([ts for ts, _ in data])

            if len(all_timestamps) < 20:
                return {
                    "is_anomaly": False,
                    "severity": "info",
                    "anomaly_score": 0.0,
                    "explanation": "Insufficient historical data",
                }

            # Build feature matrix
            sorted_timestamps = sorted(all_timestamps)
            metric_names = sorted(metrics_data.keys())
            
            # Create DataFrame with all metrics
            data_dict = {"timestamp": sorted_timestamps}
            for metric_name in metric_names:
                metric_dict = dict(metrics_data[metric_name])
                data_dict[metric_name] = [
                    metric_dict.get(ts, np.nan) for ts in sorted_timestamps
                ]

            df = pd.DataFrame(data_dict)
            
            # Filter to window
            cutoff_time = datetime.utcnow() - timedelta(hours=self.window_hours)
            df = df[df["timestamp"] >= cutoff_time]
            
            # Drop timestamp and handle missing values
            X = df.drop("timestamp", axis=1)
            X = X.fillna(X.mean())

            if len(X) < 20:
                return {
                    "is_anomaly": False,
                    "severity": "info",
                    "anomaly_score": 0.0,
                    "explanation": "Insufficient data in time window",
                }

            # Train Isolation Forest
            self.isolation_forest = IsolationForest(
                contamination=self.contamination,
                random_state=42,
                n_estimators=100,
            )
            self.isolation_forest.fit(X)

            # Predict on current values
            current_array = np.array([[current_values.get(m, 0.0) for m in metric_names]])
            prediction = self.isolation_forest.predict(current_array)[0]
            anomaly_score = -self.isolation_forest.score_samples(current_array)[0]

            is_anomaly = prediction == -1

            # Determine severity based on anomaly score
            # Anomaly score typically ranges from 0 to 1+
            if anomaly_score > 0.7:
                severity = "critical"
            elif anomaly_score > 0.5:
                severity = "warning"
            else:
                severity = "normal"

            if is_anomaly:
                metrics.increment("anomaly_detector.multivariate_anomalies")
                logger.info(
                    "Multivariate anomaly detected",
                    extra={
                        "anomaly_score": anomaly_score,
                        "severity": severity,
                        "metrics": metric_names,
                    },
                )

            explanation = (
                f"Multivariate analysis across {len(metric_names)} metrics "
                f"({'anomalous' if is_anomaly else 'normal'} pattern detected, "
                f"score: {anomaly_score:.3f})"
            )

            return {
                "is_anomaly": is_anomaly,
                "severity": severity if is_anomaly else "normal",
                "anomaly_score": round(anomaly_score, 3),
                "metrics_analyzed": metric_names,
                "explanation": explanation,
            }

        except Exception as e:
            logger.error(
                "Error in multivariate anomaly detection",
                extra={"error": str(e)},
                exc_info=True,
            )
            metrics.increment("anomaly_detector.errors")
            return {
                "is_anomaly": False,
                "severity": "error",
                "anomaly_score": 0.0,
                "explanation": f"Error during analysis: {str(e)}",
            }

    def analyze_metrics(
        self,
        metric_name: str,
        current_value: float,
        historical_data: List[Tuple[datetime, float]],
        additional_metrics: Optional[Dict[str, List[Tuple[datetime, float]]]] = None,
    ) -> Dict[str, Any]:
        """Comprehensive anomaly analysis combining Z-score and multivariate methods.

        Args:
            metric_name: Primary metric name
            current_value: Current value of primary metric
            historical_data: Historical data for primary metric
            additional_metrics: Optional additional metrics for multivariate analysis

        Returns:
            Combined anomaly detection results
        """
        metrics.increment("anomaly_detector.analyses")
        
        # Z-score analysis
        zscore_result = self.detect_zscore_anomaly(
            metric_name, current_value, historical_data
        )

        result = {
            "metric_name": metric_name,
            "timestamp": datetime.utcnow().isoformat(),
            "zscore_analysis": zscore_result,
        }

        # Multivariate analysis if additional metrics provided
        if additional_metrics and len(additional_metrics) > 0:
            all_metrics = {metric_name: historical_data}
            all_metrics.update(additional_metrics)
            
            current_values = {metric_name: current_value}
            for m, data in additional_metrics.items():
                if data:
                    current_values[m] = data[-1][1]  # Get latest value

            multivariate_result = self.detect_multivariate_anomaly(
                all_metrics, current_values
            )
            result["multivariate_analysis"] = multivariate_result

            # Overall assessment
            is_anomaly = (
                zscore_result["is_anomaly"] or multivariate_result["is_anomaly"]
            )
            severities = ["normal", "info", "warning", "critical", "extreme"]
            severity_scores = {s: i for i, s in enumerate(severities)}
            overall_severity = max(
                zscore_result["severity"],
                multivariate_result["severity"],
                key=lambda s: severity_scores.get(s, 0),
            )

            result["overall"] = {
                "is_anomaly": is_anomaly,
                "severity": overall_severity,
            }
        else:
            result["overall"] = {
                "is_anomaly": zscore_result["is_anomaly"],
                "severity": zscore_result["severity"],
            }

        return result
