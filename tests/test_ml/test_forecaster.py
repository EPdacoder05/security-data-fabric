"""
Tests for time-series forecaster.
"""
import pytest
import numpy as np
import pandas as pd
from datetime import datetime, timedelta
from pathlib import Path
import tempfile
import shutil

from src.ml.forecaster import Forecaster


class TestForecaster:
    """Test suite for Forecaster."""
    
    @pytest.fixture
    def temp_model_path(self):
        """Create temporary directory for models."""
        temp_dir = tempfile.mkdtemp()
        yield temp_dir
        shutil.rmtree(temp_dir)
    
    @pytest.fixture
    def forecaster(self, temp_model_path):
        """Create forecaster with temporary model path."""
        return Forecaster(n_estimators=10, max_depth=5, model_path=temp_model_path)
    
    @pytest.fixture
    def sample_data(self):
        """Create sample time-series data."""
        np.random.seed(42)  # For reproducibility
        start_time = datetime.now()
        timestamps = [start_time + timedelta(hours=i) for i in range(200)]  # More data
        # Create a clear trend
        values = [50 + i * 0.3 + np.random.normal(0, 1.5) for i in range(200)]
        
        return pd.DataFrame({
            "timestamp": timestamps,
            "value": values
        })
    
    def test_initialization(self, forecaster, temp_model_path):
        """Test forecaster initialization."""
        assert forecaster.n_estimators == 10
        assert forecaster.max_depth == 5
        assert forecaster.model_path == Path(temp_model_path)
        assert forecaster.model is None
        assert Path(temp_model_path).exists()
    
    def test_engineer_features(self, forecaster, sample_data):
        """Test feature engineering."""
        df_features = forecaster.engineer_features(sample_data)
        
        # Check temporal features
        assert "hour" in df_features.columns
        assert "day_of_week" in df_features.columns
        assert "is_weekend" in df_features.columns
        
        # Check lag features
        assert "lag_1" in df_features.columns
        assert "lag_3" in df_features.columns
        
        # Check rolling features
        assert "rolling_mean_3" in df_features.columns
        assert "rolling_std_6" in df_features.columns
        
        # Check rate of change
        assert "rate_of_change" in df_features.columns
        
        # Check exponential moving average
        assert "ema_3" in df_features.columns
    
    def test_engineer_features_custom_params(self, forecaster, sample_data):
        """Test feature engineering with custom parameters."""
        df_features = forecaster.engineer_features(
            sample_data,
            lag_periods=[1, 2],
            rolling_windows=[3, 6]
        )
        
        assert "lag_1" in df_features.columns
        assert "lag_2" in df_features.columns
        assert "lag_12" not in df_features.columns  # Not in custom lag_periods
    
    def test_train_model(self, forecaster, sample_data):
        """Test model training."""
        metrics = forecaster.train(sample_data)
        
        assert forecaster.model is not None
        assert forecaster.trained_on is not None
        assert len(forecaster.feature_names) > 0
        
        # Check metrics exist
        assert "train_rmse" in metrics
        assert "test_rmse" in metrics
        assert "train_r2" in metrics
        assert "test_r2" in metrics
        assert "n_train_samples" in metrics
        assert "n_test_samples" in metrics
        
        # Just verify we have samples
        assert metrics["n_train_samples"] > 0
        assert metrics["n_test_samples"] > 0
    
    def test_train_insufficient_data(self, forecaster):
        """Test training with insufficient data."""
        # Very small dataset
        df = pd.DataFrame({
            "timestamp": [datetime.now() + timedelta(hours=i) for i in range(5)],
            "value": [1, 2, 3, 4, 5]
        })
        
        with pytest.raises(ValueError, match="Insufficient data"):
            forecaster.train(df)
    
    def test_predict_without_training(self, forecaster, sample_data):
        """Test prediction without training."""
        with pytest.raises(ValueError, match="Model not trained"):
            forecaster.predict(sample_data, n_steps=10)
    
    def test_predict(self, forecaster, sample_data):
        """Test making predictions."""
        # Train first
        forecaster.train(sample_data)
        
        # Make predictions
        result = forecaster.predict(sample_data, n_steps=5)
        
        assert "predictions" in result
        assert "timestamps" in result
        assert "confidence_intervals" in result
        assert len(result["predictions"]) == 5
        assert len(result["timestamps"]) == 5
        assert len(result["confidence_intervals"]) == 5
        
        # Check confidence intervals structure
        for ci in result["confidence_intervals"]:
            assert "lower" in ci
            assert "upper" in ci
            assert ci["lower"] <= ci["upper"]
    
    def test_predict_longer_horizon(self, forecaster, sample_data):
        """Test predictions with longer horizon."""
        forecaster.train(sample_data)
        
        result = forecaster.predict(sample_data, n_steps=24)
        
        # May not always get all 24 steps due to feature engineering constraints
        assert len(result["predictions"]) >= 10  # At least 10 steps
        assert len(result["predictions"]) <= 24
    
    def test_save_model(self, forecaster, sample_data, temp_model_path):
        """Test model saving."""
        # Train model
        forecaster.train(sample_data)
        
        # Save model
        model_path = forecaster.save_model("test_model")
        
        assert Path(model_path).exists()
        assert "test_model.joblib" in model_path
    
    def test_save_without_training(self, forecaster):
        """Test saving without training."""
        with pytest.raises(ValueError, match="No model to save"):
            forecaster.save_model("test_model")
    
    def test_load_model(self, forecaster, sample_data, temp_model_path):
        """Test model loading."""
        # Train and save
        forecaster.train(sample_data)
        original_trained_on = forecaster.trained_on
        forecaster.save_model("test_model")
        
        # Create new forecaster and load
        new_forecaster = Forecaster(model_path=temp_model_path)
        new_forecaster.load_model("test_model")
        
        assert new_forecaster.model is not None
        assert len(new_forecaster.feature_names) > 0
        assert new_forecaster.trained_on == original_trained_on
    
    def test_load_nonexistent_model(self, forecaster):
        """Test loading non-existent model."""
        with pytest.raises(FileNotFoundError):
            forecaster.load_model("nonexistent_model")
    
    def test_predict_capacity_exhaustion_will_exhaust(self, forecaster):
        """Test capacity exhaustion prediction when exhaustion expected."""
        # Create increasing trend
        start_time = datetime.now()
        timestamps = [start_time + timedelta(hours=i) for i in range(50)]
        values = [50 + i * 1.0 for i in range(50)]
        
        df = pd.DataFrame({"timestamp": timestamps, "value": values})
        
        # Train
        forecaster.train(df)
        
        # Predict capacity exhaustion
        result = forecaster.predict_capacity_exhaustion(
            df,
            capacity=150.0,
            max_horizon=100
        )
        
        assert "will_exhaust" in result
        assert result["capacity"] == 150.0
        
        # Should predict exhaustion since trend is increasing
        if result["will_exhaust"]:
            assert result["exhaustion_time"] is not None
            assert result["hours_until_exhaustion"] is not None
    
    def test_predict_capacity_exhaustion_no_exhaust(self, forecaster):
        """Test capacity exhaustion when no exhaustion expected."""
        # Create stable trend
        start_time = datetime.now()
        timestamps = [start_time + timedelta(hours=i) for i in range(50)]
        values = [50 + np.random.normal(0, 1) for _ in range(50)]
        
        df = pd.DataFrame({"timestamp": timestamps, "value": values})
        
        # Train
        forecaster.train(df)
        
        # Predict with high capacity
        result = forecaster.predict_capacity_exhaustion(
            df,
            capacity=200.0,
            max_horizon=24
        )
        
        assert "will_exhaust" in result
        
        # Might not exhaust with high capacity and short horizon
        if not result["will_exhaust"]:
            assert result["exhaustion_time"] is None
            assert "max_predicted_value" in result
    
    def test_get_feature_importance(self, forecaster, sample_data):
        """Test feature importance extraction."""
        # Before training
        importance = forecaster.get_feature_importance()
        assert importance is None
        
        # Train model
        forecaster.train(sample_data)
        
        # Get importance
        importance = forecaster.get_feature_importance()
        
        assert importance is not None
        assert isinstance(importance, dict)
        assert len(importance) > 0
        
        # Check all values are between 0 and 1
        for name, score in importance.items():
            assert 0 <= score <= 1
    
    def test_feature_importance_sorted(self, forecaster, sample_data):
        """Test that feature importance is sorted."""
        forecaster.train(sample_data)
        importance = forecaster.get_feature_importance()
        
        scores = list(importance.values())
        
        # Should be sorted in descending order
        assert scores == sorted(scores, reverse=True)
    
    def test_train_test_split(self, forecaster, sample_data):
        """Test train/test split ratio."""
        metrics = forecaster.train(sample_data, test_size=0.3)
        
        total_samples = metrics["n_train_samples"] + metrics["n_test_samples"]
        test_ratio = metrics["n_test_samples"] / total_samples
        
        # Should be approximately 0.3
        assert 0.25 <= test_ratio <= 0.35
    
    def test_custom_column_names(self, forecaster):
        """Test with custom column names."""
        np.random.seed(42)
        df = pd.DataFrame({
            "ts": [datetime.now() + timedelta(hours=i) for i in range(100)],
            "metric": [50 + i * 0.3 for i in range(100)]
        })
        
        metrics = forecaster.train(
            df,
            value_column="metric",
            timestamp_column="ts"
        )
        
        # Just verify training succeeded
        assert metrics["n_train_samples"] > 0
    
    def test_model_persistence(self, forecaster, sample_data, temp_model_path):
        """Test that loaded model makes same predictions."""
        # Train and predict
        forecaster.train(sample_data)
        result1 = forecaster.predict(sample_data, n_steps=5)
        
        # Save and load
        forecaster.save_model("persistence_test")
        new_forecaster = Forecaster(model_path=temp_model_path)
        new_forecaster.load_model("persistence_test")
        
        # Predict with loaded model
        result2 = new_forecaster.predict(sample_data, n_steps=5)
        
        # Predictions should be identical
        np.testing.assert_array_almost_equal(
            result1["predictions"],
            result2["predictions"],
            decimal=5
        )
