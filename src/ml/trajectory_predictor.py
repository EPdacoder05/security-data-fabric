"""Time-to-breach trajectory predictions for resource exhaustion scenarios."""
import numpy as np
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Optional, Any
from enum import Enum

from src.observability.logging import get_logger
from src.observability.metrics import metrics

logger = get_logger(__name__)


class PredictionType(str, Enum):
    """Types of trajectory predictions."""
    
    CPU_EXHAUSTION = "cpu_exhaustion"
    MEMORY_EXHAUSTION = "memory_exhaustion"
    DISK_FULL = "disk_full"
    NETWORK_SATURATION = "network_saturation"


class TrajectoryPredictor:
    """Predicts time-to-breach using linear trajectory extrapolation."""

    def __init__(self, min_data_points: int = 5) -> None:
        """Initialize trajectory predictor.

        Args:
            min_data_points: Minimum number of data points required for prediction
        """
        self.min_data_points = min_data_points
        logger.info(
            "Initialized TrajectoryPredictor",
            extra={"min_data_points": min_data_points},
        )

    def calculate_growth_rate(
        self, data_points: List[Tuple[datetime, float]]
    ) -> Tuple[float, float, float]:
        """Calculate growth rate using linear regression.

        Args:
            data_points: List of (timestamp, value) tuples

        Returns:
            Tuple of (slope, intercept, r_squared)
        """
        if len(data_points) < 2:
            return 0.0, 0.0, 0.0

        # Convert to arrays
        timestamps = np.array([(ts - data_points[0][0]).total_seconds() for ts, _ in data_points])
        values = np.array([val for _, val in data_points])

        # Linear regression using least squares
        n = len(timestamps)
        sum_x = np.sum(timestamps)
        sum_y = np.sum(values)
        sum_xx = np.sum(timestamps * timestamps)
        sum_xy = np.sum(timestamps * values)

        # Calculate slope and intercept
        denominator = n * sum_xx - sum_x * sum_x
        if denominator == 0:
            return 0.0, values[0], 0.0

        slope = (n * sum_xy - sum_x * sum_y) / denominator
        intercept = (sum_y - slope * sum_x) / n

        # Calculate R-squared
        y_pred = slope * timestamps + intercept
        ss_res = np.sum((values - y_pred) ** 2)
        ss_tot = np.sum((values - np.mean(values)) ** 2)
        
        r_squared = 1 - (ss_res / ss_tot) if ss_tot != 0 else 0.0
        r_squared = max(0.0, min(1.0, r_squared))  # Clamp to [0, 1]

        return float(slope), float(intercept), float(r_squared)

    def calculate_confidence(
        self,
        r_squared: float,
        data_points: int,
        time_horizon_minutes: int,
    ) -> float:
        """Calculate prediction confidence score.

        Args:
            r_squared: R-squared value from linear regression
            data_points: Number of data points used
            time_horizon_minutes: Prediction time horizon

        Returns:
            Confidence score between 0 and 1
        """
        # Base confidence from R-squared
        confidence = r_squared

        # Adjust for sample size
        if data_points < 10:
            confidence *= 0.7
        elif data_points < 20:
            confidence *= 0.85

        # Reduce confidence for longer time horizons
        if time_horizon_minutes > 1440:  # > 24 hours
            confidence *= 0.6
        elif time_horizon_minutes > 720:  # > 12 hours
            confidence *= 0.75
        elif time_horizon_minutes > 360:  # > 6 hours
            confidence *= 0.9

        return max(0.0, min(1.0, confidence))

    def predict_time_to_breach(
        self,
        metric_name: str,
        historical_data: List[Tuple[datetime, float]],
        threshold: float,
        prediction_type: PredictionType,
    ) -> Dict[str, Any]:
        """Predict time until a threshold is breached.

        Args:
            metric_name: Name of the metric
            historical_data: List of (timestamp, value) tuples
            threshold: Threshold value that constitutes a breach
            prediction_type: Type of prediction being made

        Returns:
            Dictionary with prediction results
        """
        metrics.increment("trajectory_predictor.predictions")
        
        try:
            if len(historical_data) < self.min_data_points:
                logger.warning(
                    "Insufficient data for trajectory prediction",
                    extra={
                        "metric": metric_name,
                        "data_points": len(historical_data),
                        "required": self.min_data_points,
                    },
                )
                return {
                    "prediction_type": prediction_type.value,
                    "metric_name": metric_name,
                    "will_breach": False,
                    "time_to_breach_minutes": None,
                    "confidence": 0.0,
                    "explanation": "Insufficient historical data for prediction",
                }

            # Sort by timestamp
            sorted_data = sorted(historical_data, key=lambda x: x[0])
            current_value = sorted_data[-1][1]
            current_time = sorted_data[-1][0]

            # Calculate growth rate
            slope, intercept, r_squared = self.calculate_growth_rate(sorted_data)

            # Check if approaching threshold
            if slope <= 0 and current_value < threshold:
                return {
                    "prediction_type": prediction_type.value,
                    "metric_name": metric_name,
                    "current_value": round(current_value, 3),
                    "threshold": threshold,
                    "will_breach": False,
                    "time_to_breach_minutes": None,
                    "growth_rate": round(slope, 6),
                    "confidence": round(r_squared, 3),
                    "explanation": f"{metric_name} is not growing towards threshold",
                }

            if slope <= 0 and current_value >= threshold:
                return {
                    "prediction_type": prediction_type.value,
                    "metric_name": metric_name,
                    "current_value": round(current_value, 3),
                    "threshold": threshold,
                    "will_breach": True,
                    "time_to_breach_minutes": 0,
                    "growth_rate": round(slope, 6),
                    "confidence": 1.0,
                    "explanation": f"{metric_name} has already breached threshold",
                }

            # Calculate time to breach
            time_elapsed = (current_time - sorted_data[0][0]).total_seconds()
            
            # Extrapolate: value = slope * time + intercept
            # Solve for time when value = threshold
            time_to_threshold_seconds = (threshold - intercept) / slope if slope != 0 else float('inf')
            
            # Current time in model coordinates
            current_time_seconds = time_elapsed
            
            # Time remaining until breach
            time_remaining_seconds = time_to_threshold_seconds - current_time_seconds
            time_to_breach_minutes = int(time_remaining_seconds / 60)

            if time_to_breach_minutes <= 0:
                will_breach = True
                time_to_breach_minutes = 0
                explanation = f"{metric_name} has breached or is at threshold"
            else:
                will_breach = True
                breach_time = current_time + timedelta(seconds=time_remaining_seconds)
                explanation = (
                    f"{metric_name} projected to reach {threshold} in "
                    f"{time_to_breach_minutes} minutes (at {breach_time.strftime('%Y-%m-%d %H:%M:%S')} UTC)"
                )

            # Calculate confidence
            confidence = self.calculate_confidence(
                r_squared, len(sorted_data), time_to_breach_minutes
            )

            # Determine severity based on time to breach
            if time_to_breach_minutes <= 15:
                severity = 5  # Critical
            elif time_to_breach_minutes <= 60:
                severity = 4  # High
            elif time_to_breach_minutes <= 240:
                severity = 3  # Medium
            else:
                severity = 2  # Low

            metrics.increment("trajectory_predictor.breaches_predicted")
            logger.info(
                "Trajectory prediction completed",
                extra={
                    "metric": metric_name,
                    "prediction_type": prediction_type.value,
                    "time_to_breach": time_to_breach_minutes,
                    "confidence": confidence,
                },
            )

            return {
                "prediction_type": prediction_type.value,
                "metric_name": metric_name,
                "current_value": round(current_value, 3),
                "threshold": threshold,
                "will_breach": will_breach,
                "time_to_breach_minutes": time_to_breach_minutes,
                "breach_timestamp": (
                    (datetime.utcnow() + timedelta(minutes=time_to_breach_minutes)).isoformat()
                    if will_breach and time_to_breach_minutes > 0
                    else None
                ),
                "growth_rate": round(slope, 6),
                "growth_rate_per_hour": round(slope * 3600, 3),
                "confidence": round(confidence, 3),
                "r_squared": round(r_squared, 3),
                "data_points_used": len(sorted_data),
                "severity": severity,
                "explanation": explanation,
            }

        except Exception as e:
            logger.error(
                "Error in trajectory prediction",
                extra={
                    "metric": metric_name,
                    "prediction_type": prediction_type.value,
                    "error": str(e),
                },
                exc_info=True,
            )
            metrics.increment("trajectory_predictor.errors")
            return {
                "prediction_type": prediction_type.value,
                "metric_name": metric_name,
                "will_breach": False,
                "time_to_breach_minutes": None,
                "confidence": 0.0,
                "explanation": f"Error during prediction: {str(e)}",
            }

    def predict_resource_exhaustion(
        self,
        cpu_data: Optional[List[Tuple[datetime, float]]] = None,
        memory_data: Optional[List[Tuple[datetime, float]]] = None,
        disk_data: Optional[List[Tuple[datetime, float]]] = None,
        network_data: Optional[List[Tuple[datetime, float]]] = None,
        cpu_threshold: float = 95.0,
        memory_threshold: float = 95.0,
        disk_threshold: float = 95.0,
        network_threshold: float = 95.0,
    ) -> List[Dict[str, Any]]:
        """Predict multiple resource exhaustion scenarios.

        Args:
            cpu_data: CPU utilization data (percentage)
            memory_data: Memory utilization data (percentage)
            disk_data: Disk utilization data (percentage)
            network_data: Network utilization data (percentage)
            cpu_threshold: CPU breach threshold
            memory_threshold: Memory breach threshold
            disk_threshold: Disk breach threshold
            network_threshold: Network breach threshold

        Returns:
            List of prediction results for each resource
        """
        predictions = []

        if cpu_data:
            predictions.append(
                self.predict_time_to_breach(
                    "cpu_utilization",
                    cpu_data,
                    cpu_threshold,
                    PredictionType.CPU_EXHAUSTION,
                )
            )

        if memory_data:
            predictions.append(
                self.predict_time_to_breach(
                    "memory_utilization",
                    memory_data,
                    memory_threshold,
                    PredictionType.MEMORY_EXHAUSTION,
                )
            )

        if disk_data:
            predictions.append(
                self.predict_time_to_breach(
                    "disk_utilization",
                    disk_data,
                    disk_threshold,
                    PredictionType.DISK_FULL,
                )
            )

        if network_data:
            predictions.append(
                self.predict_time_to_breach(
                    "network_utilization",
                    network_data,
                    network_threshold,
                    PredictionType.NETWORK_SATURATION,
                )
            )

        # Sort by time to breach (most urgent first)
        predictions.sort(
            key=lambda p: (
                p["time_to_breach_minutes"]
                if p["will_breach"] and p["time_to_breach_minutes"] is not None
                else float("inf")
            )
        )

        return predictions
