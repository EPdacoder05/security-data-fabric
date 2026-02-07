"""
Time-to-breach prediction engine for Security Data Fabric.
Implements linear trajectory extrapolation and capacity planning predictions.
"""
import logging
from datetime import datetime, timedelta
from enum import Enum
from typing import Dict, List, Optional, Tuple
import numpy as np
import pandas as pd
from scipy import stats

from src.config.settings import settings

logger = logging.getLogger(__name__)


class PredictionType(str, Enum):
    """Types of resource exhaustion predictions."""
    CPU_EXHAUSTION = "cpu_exhaustion"
    MEMORY_EXHAUSTION = "memory_exhaustion"
    DISK_FULL = "disk_full"
    ERROR_RATE_SPIKE = "error_rate_spike"


class TrajectoryPredictor:
    """
    Time-to-breach prediction using linear trajectory extrapolation.
    
    Predicts when a metric will cross a critical threshold based on
    current trends, useful for capacity planning and proactive alerting.
    """
    
    def __init__(self, confidence_threshold: Optional[float] = None):
        """
        Initialize trajectory predictor.
        
        Args:
            confidence_threshold: Minimum confidence for predictions
                                (uses ml_confidence_threshold from settings if None)
        """
        self.confidence_threshold = confidence_threshold or settings.ml_confidence_threshold
        logger.info(f"TrajectoryPredictor initialized: confidence_threshold={self.confidence_threshold}")
    
    def predict_time_to_breach(
        self,
        timestamps: List[datetime],
        values: List[float],
        threshold: float,
        prediction_type: PredictionType,
        increasing_is_breach: bool = True
    ) -> Dict:
        """
        Predict when a metric will breach a threshold.
        
        Args:
            timestamps: List of timestamps for historical data
            values: List of metric values corresponding to timestamps
            threshold: Critical threshold value
            prediction_type: Type of prediction being made
            increasing_is_breach: True if breaching means exceeding threshold,
                                 False if breaching means going below threshold
        
        Returns:
            Dictionary containing:
                - time_to_breach: timedelta until breach (None if no breach predicted)
                - breach_time: datetime of predicted breach (None if no breach)
                - confidence: confidence score (0-1)
                - growth_rate: rate of change per hour
                - current_value: latest metric value
                - prediction_type: type of prediction
                - explanation: human-readable explanation
        """
        try:
            # Validate inputs
            if len(timestamps) < 3 or len(values) < 3:
                return self._no_prediction_result(
                    prediction_type,
                    "Insufficient data points (minimum 3 required)",
                    values[-1] if values else None
                )
            
            if len(timestamps) != len(values):
                return self._no_prediction_result(
                    prediction_type,
                    "Mismatched timestamps and values",
                    values[-1] if values else None
                )
            
            # Convert to numpy arrays
            time_hours = self._convert_to_hours(timestamps)
            values_array = np.array(values, dtype=float)
            
            # Calculate linear regression
            slope, intercept, r_value, p_value, std_err = stats.linregress(time_hours, values_array)
            
            # Calculate confidence based on R² and p-value
            r_squared = r_value ** 2
            confidence = self._calculate_confidence(r_squared, p_value, len(values))
            
            # Get current value and time
            current_value = values_array[-1]
            current_time = timestamps[-1]
            
            # Calculate growth rate (per hour)
            growth_rate = slope
            
            # Check if trend is moving toward breach
            if increasing_is_breach and slope <= 0:
                return self._no_prediction_result(
                    prediction_type,
                    f"Trend is decreasing (rate: {growth_rate:.4f}/hr), no breach expected",
                    current_value,
                    confidence,
                    growth_rate
                )
            
            if not increasing_is_breach and slope >= 0:
                return self._no_prediction_result(
                    prediction_type,
                    f"Trend is increasing (rate: {growth_rate:.4f}/hr), no breach expected",
                    current_value,
                    confidence,
                    growth_rate
                )
            
            # Calculate time to breach
            if abs(slope) < 1e-10:  # Effectively zero slope
                return self._no_prediction_result(
                    prediction_type,
                    "Metric is stable, no breach predicted",
                    current_value,
                    confidence,
                    growth_rate
                )
            
            hours_to_breach = (threshold - current_value) / slope
            
            # Check if already breached
            if hours_to_breach <= 0:
                breach_time = current_time
                time_to_breach = timedelta(0)
                explanation = (
                    f"Threshold already breached: {current_value:.2f} vs {threshold:.2f}"
                )
            else:
                time_to_breach = timedelta(hours=hours_to_breach)
                breach_time = current_time + time_to_breach
                explanation = self._generate_explanation(
                    prediction_type,
                    current_value,
                    threshold,
                    time_to_breach,
                    growth_rate,
                    confidence
                )
            
            result = {
                "time_to_breach": time_to_breach,
                "breach_time": breach_time,
                "confidence": confidence,
                "growth_rate": growth_rate,
                "current_value": current_value,
                "threshold": threshold,
                "prediction_type": prediction_type.value,
                "explanation": explanation,
                "r_squared": r_squared,
                "meets_confidence_threshold": confidence >= self.confidence_threshold
            }
            
            logger.info(
                f"Breach prediction for {prediction_type.value}: "
                f"TTB={time_to_breach}, confidence={confidence:.2f}"
            )
            
            return result
            
        except Exception as e:
            logger.error(f"Error in time-to-breach prediction: {e}")
            return self._no_prediction_result(
                prediction_type,
                f"Prediction error: {str(e)}",
                values[-1] if values else None
            )
    
    def predict_capacity_exhaustion(
        self,
        timestamps: List[datetime],
        values: List[float],
        capacity: float,
        resource_name: str = "resource"
    ) -> Dict:
        """
        Predict when a resource will reach capacity.
        
        Args:
            timestamps: List of timestamps
            values: List of resource usage values
            capacity: Maximum capacity
            resource_name: Name of resource for logging
        
        Returns:
            Prediction dictionary
        """
        # Determine prediction type based on resource name
        prediction_type = PredictionType.MEMORY_EXHAUSTION
        if "cpu" in resource_name.lower():
            prediction_type = PredictionType.CPU_EXHAUSTION
        elif "disk" in resource_name.lower():
            prediction_type = PredictionType.DISK_FULL
        
        # Typically want to alert before 100% capacity (e.g., at 90%)
        warning_threshold = capacity * 0.9
        
        return self.predict_time_to_breach(
            timestamps=timestamps,
            values=values,
            threshold=warning_threshold,
            prediction_type=prediction_type,
            increasing_is_breach=True
        )
    
    def predict_error_rate_spike(
        self,
        timestamps: List[datetime],
        error_rates: List[float],
        critical_rate: float = 0.05
    ) -> Dict:
        """
        Predict when error rate will reach critical level.
        
        Args:
            timestamps: List of timestamps
            error_rates: List of error rates (0-1 scale)
            critical_rate: Critical error rate threshold
        
        Returns:
            Prediction dictionary
        """
        return self.predict_time_to_breach(
            timestamps=timestamps,
            values=error_rates,
            threshold=critical_rate,
            prediction_type=PredictionType.ERROR_RATE_SPIKE,
            increasing_is_breach=True
        )
    
    def _convert_to_hours(self, timestamps: List[datetime]) -> np.ndarray:
        """Convert timestamps to hours since first timestamp."""
        first_time = timestamps[0]
        hours = [(t - first_time).total_seconds() / 3600 for t in timestamps]
        return np.array(hours)
    
    def _calculate_confidence(
        self,
        r_squared: float,
        p_value: float,
        n_samples: int
    ) -> float:
        """
        Calculate confidence score based on regression quality.
        
        Combines R² value, statistical significance, and sample size.
        """
        # Base confidence from R²
        confidence = r_squared
        
        # Penalty for high p-value (not statistically significant)
        if p_value > 0.05:
            confidence *= 0.5
        elif p_value > 0.01:
            confidence *= 0.8
        
        # Penalty for small sample size
        if n_samples < 5:
            confidence *= 0.5
        elif n_samples < 10:
            confidence *= 0.8
        
        return min(max(confidence, 0.0), 1.0)
    
    def _generate_explanation(
        self,
        prediction_type: PredictionType,
        current_value: float,
        threshold: float,
        time_to_breach: timedelta,
        growth_rate: float,
        confidence: float
    ) -> str:
        """Generate human-readable explanation."""
        hours = time_to_breach.total_seconds() / 3600
        
        if hours < 1:
            time_str = f"{int(time_to_breach.total_seconds() / 60)} minutes"
        elif hours < 24:
            time_str = f"{hours:.1f} hours"
        else:
            days = hours / 24
            time_str = f"{days:.1f} days"
        
        return (
            f"{prediction_type.value.replace('_', ' ').title()}: "
            f"Current value {current_value:.2f} will reach threshold {threshold:.2f} "
            f"in approximately {time_str} (growth rate: {growth_rate:.4f}/hr, "
            f"confidence: {confidence:.1%})"
        )
    
    def _no_prediction_result(
        self,
        prediction_type: PredictionType,
        explanation: str,
        current_value: Optional[float],
        confidence: float = 0.0,
        growth_rate: Optional[float] = None
    ) -> Dict:
        """Return result when no breach is predicted."""
        result = {
            "time_to_breach": None,
            "breach_time": None,
            "confidence": confidence,
            "growth_rate": growth_rate,
            "current_value": current_value,
            "threshold": None,
            "prediction_type": prediction_type.value,
            "explanation": explanation,
            "r_squared": None,
            "meets_confidence_threshold": False
        }
        
        logger.debug(f"No breach prediction for {prediction_type.value}: {explanation}")
        return result
    
    def analyze_trend(
        self,
        timestamps: List[datetime],
        values: List[float]
    ) -> Dict:
        """
        Analyze trend without predicting breach.
        
        Returns trend direction, growth rate, and confidence.
        """
        try:
            if len(timestamps) < 2 or len(values) < 2:
                return {
                    "trend": "unknown",
                    "growth_rate": 0.0,
                    "confidence": 0.0,
                    "explanation": "Insufficient data"
                }
            
            time_hours = self._convert_to_hours(timestamps)
            values_array = np.array(values)
            
            slope, intercept, r_value, p_value, std_err = stats.linregress(time_hours, values_array)
            r_squared = r_value ** 2
            confidence = self._calculate_confidence(r_squared, p_value, len(values))
            
            # Determine trend
            if abs(slope) < 1e-6:
                trend = "stable"
            elif slope > 0:
                trend = "increasing"
            else:
                trend = "decreasing"
            
            return {
                "trend": trend,
                "growth_rate": slope,
                "confidence": confidence,
                "r_squared": r_squared,
                "current_value": values_array[-1],
                "explanation": f"Trend is {trend} at rate {slope:.4f}/hr (R²={r_squared:.3f})"
            }
            
        except Exception as e:
            logger.error(f"Error analyzing trend: {e}")
            return {
                "trend": "error",
                "growth_rate": 0.0,
                "confidence": 0.0,
                "explanation": f"Analysis error: {str(e)}"
            }
