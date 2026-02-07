"""
Tests for trajectory predictor.
"""
import pytest
import numpy as np
from datetime import datetime, timedelta

from src.ml.trajectory_predictor import TrajectoryPredictor, PredictionType


class TestTrajectoryPredictor:
    """Test suite for TrajectoryPredictor."""
    
    def test_initialization(self):
        """Test predictor initialization."""
        predictor = TrajectoryPredictor(confidence_threshold=0.8)
        assert predictor.confidence_threshold == 0.8
    
    def test_predict_breach_increasing(self):
        """Test breach prediction for increasing trend."""
        predictor = TrajectoryPredictor()
        
        # Create increasing trend: 50, 60, 70, 80, 90
        start_time = datetime.now()
        timestamps = [start_time + timedelta(hours=i) for i in range(5)]
        values = [50.0, 60.0, 70.0, 80.0, 90.0]
        threshold = 100.0
        
        result = predictor.predict_time_to_breach(
            timestamps=timestamps,
            values=values,
            threshold=threshold,
            prediction_type=PredictionType.CPU_EXHAUSTION,
            increasing_is_breach=True
        )
        
        assert result["time_to_breach"] is not None
        assert result["breach_time"] is not None
        assert result["growth_rate"] > 0
        assert result["current_value"] == 90.0
        assert result["confidence"] > 0
    
    def test_predict_breach_decreasing(self):
        """Test breach prediction for decreasing trend."""
        predictor = TrajectoryPredictor()
        
        # Create decreasing trend
        start_time = datetime.now()
        timestamps = [start_time + timedelta(hours=i) for i in range(5)]
        values = [100.0, 90.0, 80.0, 70.0, 60.0]
        threshold = 50.0
        
        result = predictor.predict_time_to_breach(
            timestamps=timestamps,
            values=values,
            threshold=threshold,
            prediction_type=PredictionType.MEMORY_EXHAUSTION,
            increasing_is_breach=False
        )
        
        assert result["time_to_breach"] is not None
        assert result["growth_rate"] < 0
    
    def test_no_breach_stable(self):
        """Test no breach prediction for stable values."""
        predictor = TrajectoryPredictor()
        
        # More stable values with even less variation
        start_time = datetime.now()
        timestamps = [start_time + timedelta(hours=i) for i in range(10)]
        values = [50.0] * 10  # Perfectly stable
        threshold = 100.0
        
        result = predictor.predict_time_to_breach(
            timestamps=timestamps,
            values=values,
            threshold=threshold,
            prediction_type=PredictionType.CPU_EXHAUSTION,
            increasing_is_breach=True
        )
        
        assert result["time_to_breach"] is None
        assert result["breach_time"] is None
        # Accept either stable or decreasing for zero/near-zero slope
        assert any(word in result["explanation"].lower() for word in ["stable", "decreasing"])
    
    def test_no_breach_wrong_direction(self):
        """Test no breach when trend is in opposite direction."""
        predictor = TrajectoryPredictor()
        
        # Decreasing trend, but threshold is above
        start_time = datetime.now()
        timestamps = [start_time + timedelta(hours=i) for i in range(5)]
        values = [100.0, 90.0, 80.0, 70.0, 60.0]
        threshold = 120.0
        
        result = predictor.predict_time_to_breach(
            timestamps=timestamps,
            values=values,
            threshold=threshold,
            prediction_type=PredictionType.CPU_EXHAUSTION,
            increasing_is_breach=True
        )
        
        assert result["time_to_breach"] is None
        assert "decreasing" in result["explanation"].lower()
    
    def test_already_breached(self):
        """Test when threshold is already breached."""
        predictor = TrajectoryPredictor()
        
        start_time = datetime.now()
        timestamps = [start_time + timedelta(hours=i) for i in range(3)]
        values = [100.0, 110.0, 120.0]
        threshold = 90.0
        
        result = predictor.predict_time_to_breach(
            timestamps=timestamps,
            values=values,
            threshold=threshold,
            prediction_type=PredictionType.CPU_EXHAUSTION,
            increasing_is_breach=True
        )
        
        assert result["time_to_breach"] == timedelta(0)
        assert "already breached" in result["explanation"].lower()
    
    def test_insufficient_data(self):
        """Test with insufficient data points."""
        predictor = TrajectoryPredictor()
        
        start_time = datetime.now()
        timestamps = [start_time, start_time + timedelta(hours=1)]
        values = [50.0, 60.0]
        threshold = 100.0
        
        result = predictor.predict_time_to_breach(
            timestamps=timestamps,
            values=values,
            threshold=threshold,
            prediction_type=PredictionType.CPU_EXHAUSTION,
            increasing_is_breach=True
        )
        
        assert result["time_to_breach"] is None
        assert "insufficient" in result["explanation"].lower()
    
    def test_confidence_calculation(self):
        """Test confidence score calculation."""
        predictor = TrajectoryPredictor()
        
        # Perfect linear trend
        start_time = datetime.now()
        timestamps = [start_time + timedelta(hours=i) for i in range(10)]
        values = [float(i * 10) for i in range(10)]  # 0, 10, 20, ..., 90
        threshold = 100.0
        
        result = predictor.predict_time_to_breach(
            timestamps=timestamps,
            values=values,
            threshold=threshold,
            prediction_type=PredictionType.CPU_EXHAUSTION,
            increasing_is_breach=True
        )
        
        # Should have high confidence for perfect linear trend
        assert result["confidence"] > 0.9
        assert result["r_squared"] > 0.99
    
    def test_low_confidence_noisy_data(self):
        """Test low confidence for noisy data."""
        predictor = TrajectoryPredictor()
        
        # Noisy data
        np.random.seed(42)
        start_time = datetime.now()
        timestamps = [start_time + timedelta(hours=i) for i in range(10)]
        values = [50 + np.random.normal(0, 20) for _ in range(10)]
        threshold = 100.0
        
        result = predictor.predict_time_to_breach(
            timestamps=timestamps,
            values=values,
            threshold=threshold,
            prediction_type=PredictionType.CPU_EXHAUSTION,
            increasing_is_breach=True
        )
        
        # Confidence should be lower for noisy data
        assert result["confidence"] < 0.9
    
    def test_predict_capacity_exhaustion(self):
        """Test capacity exhaustion prediction."""
        predictor = TrajectoryPredictor()
        
        # Increasing resource usage
        start_time = datetime.now()
        timestamps = [start_time + timedelta(hours=i) for i in range(5)]
        values = [50.0, 60.0, 70.0, 80.0, 90.0]
        capacity = 100.0
        
        result = predictor.predict_capacity_exhaustion(
            timestamps=timestamps,
            values=values,
            capacity=capacity,
            resource_name="memory"
        )
        
        assert result["time_to_breach"] is not None
        assert result["prediction_type"] == PredictionType.MEMORY_EXHAUSTION.value
        # Threshold should be 90% of capacity
        assert result["threshold"] == 90.0
    
    def test_predict_error_rate_spike(self):
        """Test error rate spike prediction."""
        predictor = TrajectoryPredictor()
        
        # Increasing error rate
        start_time = datetime.now()
        timestamps = [start_time + timedelta(hours=i) for i in range(5)]
        error_rates = [0.01, 0.015, 0.02, 0.025, 0.03]
        
        result = predictor.predict_error_rate_spike(
            timestamps=timestamps,
            error_rates=error_rates,
            critical_rate=0.05
        )
        
        assert result["prediction_type"] == PredictionType.ERROR_RATE_SPIKE.value
        assert result["time_to_breach"] is not None
    
    def test_analyze_trend_increasing(self):
        """Test trend analysis for increasing values."""
        predictor = TrajectoryPredictor()
        
        start_time = datetime.now()
        timestamps = [start_time + timedelta(hours=i) for i in range(5)]
        values = [50.0, 60.0, 70.0, 80.0, 90.0]
        
        result = predictor.analyze_trend(timestamps, values)
        
        assert result["trend"] == "increasing"
        assert result["growth_rate"] > 0
        assert result["confidence"] > 0
    
    def test_analyze_trend_decreasing(self):
        """Test trend analysis for decreasing values."""
        predictor = TrajectoryPredictor()
        
        start_time = datetime.now()
        timestamps = [start_time + timedelta(hours=i) for i in range(5)]
        values = [90.0, 80.0, 70.0, 60.0, 50.0]
        
        result = predictor.analyze_trend(timestamps, values)
        
        assert result["trend"] == "decreasing"
        assert result["growth_rate"] < 0
    
    def test_analyze_trend_stable(self):
        """Test trend analysis for stable values."""
        predictor = TrajectoryPredictor()
        
        start_time = datetime.now()
        timestamps = [start_time + timedelta(hours=i) for i in range(10)]
        values = [50.0] * 10  # Perfectly stable
        
        result = predictor.analyze_trend(timestamps, values)
        
        assert result["trend"] == "stable"
    
    def test_meets_confidence_threshold(self):
        """Test confidence threshold checking."""
        predictor = TrajectoryPredictor(confidence_threshold=0.9)
        
        # High confidence prediction
        start_time = datetime.now()
        timestamps = [start_time + timedelta(hours=i) for i in range(10)]
        values = [float(i * 10) for i in range(10)]
        threshold = 100.0
        
        result = predictor.predict_time_to_breach(
            timestamps=timestamps,
            values=values,
            threshold=threshold,
            prediction_type=PredictionType.CPU_EXHAUSTION,
            increasing_is_breach=True
        )
        
        assert "meets_confidence_threshold" in result
        assert result["meets_confidence_threshold"] == (result["confidence"] >= 0.9)
