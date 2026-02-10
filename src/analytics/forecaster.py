"""ML-based incident trend forecasting with Random Forest."""
import logging
import pickle
import time
from datetime import timedelta
from typing import Any, Dict, List, Optional

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestRegressor
from sklearn.metrics import mean_squared_error, r2_score
from sklearn.model_selection import train_test_split

from src.security.redis_cache import cached

logger = logging.getLogger(__name__)


class IncidentForecaster:
    """ML-based incident forecasting using Random Forest."""

    def __init__(self, n_estimators: int = 100, random_state: int = 42) -> None:
        """Initialize forecaster.
        
        Args:
            n_estimators: Number of decision trees (default: 100)
            random_state: Random seed for reproducibility
        """
        self.model = RandomForestRegressor(
            n_estimators=n_estimators,
            max_depth=10,
            min_samples_split=5,
            min_samples_leaf=2,
            random_state=random_state,
            n_jobs=-1  # Use all CPU cores
        )
        self.is_trained = False
        self.feature_importance: Optional[Dict[str, float]] = None
        self.model_metrics: Optional[Dict[str, float]] = None

    def _engineer_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Engineer 9 features for ML model.
        
        Features:
            1. day_of_week (0-6)
            2. month (1-12)
            3-5. lag_1, lag_7, lag_30 (previous incident counts)
            6-8. rolling_avg_7, rolling_avg_14, rolling_avg_30 (moving averages)
            9. trend (linear trend over time)
        
        Args:
            df: DataFrame with 'timestamp' and 'incident_count' columns
            
        Returns:
            DataFrame with engineered features
        """
        # Ensure sorted by timestamp
        df = df.sort_values('timestamp').copy()

        # Extract time-based features
        df['day_of_week'] = df['timestamp'].dt.dayofweek
        df['month'] = df['timestamp'].dt.month

        # Lag features (previous values)
        df['lag_1'] = df['incident_count'].shift(1)
        df['lag_7'] = df['incident_count'].shift(7)
        df['lag_30'] = df['incident_count'].shift(30)

        # Rolling average features
        df['rolling_avg_7'] = df['incident_count'].rolling(window=7, min_periods=1).mean()
        df['rolling_avg_14'] = df['incident_count'].rolling(window=14, min_periods=1).mean()
        df['rolling_avg_30'] = df['incident_count'].rolling(window=30, min_periods=1).mean()

        # Trend feature (days since start)
        df['trend'] = (df['timestamp'] - df['timestamp'].min()).dt.days

        # Fill NaN values from lag features
        df = df.bfill().fillna(0)

        return df

    def train(
        self,
        historical_data: List[Dict[str, Any]],
        test_size: float = 0.2
    ) -> Dict[str, float]:
        """Train the forecasting model.
        
        Args:
            historical_data: List of dicts with 'timestamp' and 'incident_count'
            test_size: Fraction of data for testing (default: 0.2)
            
        Returns:
            Model metrics (mse, rmse, r2_score)
            
        Example:
            data = [
                {"timestamp": "2024-01-01", "incident_count": 45},
                {"timestamp": "2024-01-02", "incident_count": 52},
                ...
            ]
            metrics = forecaster.train(data)
        """
        start_time = time.perf_counter()

        # Convert to DataFrame
        df = pd.DataFrame(historical_data)
        df['timestamp'] = pd.to_datetime(df['timestamp'])

        # Engineer features
        df = self._engineer_features(df)

        # Prepare features and target
        feature_cols = [
            'day_of_week', 'month',
            'lag_1', 'lag_7', 'lag_30',
            'rolling_avg_7', 'rolling_avg_14', 'rolling_avg_30',
            'trend'
        ]

        X = df[feature_cols].values
        y = df['incident_count'].values

        # Train-test split
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=test_size, shuffle=False  # Don't shuffle time series
        )

        # Train model
        self.model.fit(X_train, y_train)
        self.is_trained = True

        # Evaluate on test set
        y_pred = self.model.predict(X_test)

        mse = mean_squared_error(y_test, y_pred)
        rmse = np.sqrt(mse)
        r2 = r2_score(y_test, y_pred)

        # Store feature importance
        self.feature_importance = dict(zip(feature_cols, self.model.feature_importances_))

        # Store metrics
        self.model_metrics = {
            "mse": float(mse),
            "rmse": float(rmse),
            "r2_score": float(r2),
            "training_samples": len(X_train),
            "test_samples": len(X_test)
        }

        duration = (time.perf_counter() - start_time) * 1000

        logger.info(
            "Model trained: samples=%d, r2=%.4f, rmse=%.2f, duration=%.2fms",
            len(X),
            r2,
            rmse,
            duration
        )

        return self.model_metrics

    @cached(ttl=3600, namespace="forecast")
    async def predict(
        self,
        historical_data: List[Dict[str, Any]],
        days_ahead: int = 7,
        confidence_level: float = 0.95
    ) -> Dict[str, Any]:
        """Predict future incident counts.
        
        Args:
            historical_data: Recent historical data for context
            days_ahead: Number of days to forecast (default: 7)
            confidence_level: Confidence interval (default: 0.95)
            
        Returns:
            Forecast with predictions and confidence intervals
            
        Performance: <500ms prediction requirement
        """
        start_time = time.perf_counter()

        if not self.is_trained:
            raise ValueError("Model not trained. Call train() first.")

        # Convert to DataFrame
        df = pd.DataFrame(historical_data)
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        df = self._engineer_features(df)

        # Generate future dates
        last_date = df['timestamp'].max()
        future_dates = [last_date + timedelta(days=i+1) for i in range(days_ahead)]

        predictions = []

        for future_date in future_dates:
            # Get most recent data for lag features
            recent_df = df.tail(30).copy()

            # Create feature vector for prediction
            features = {
                'day_of_week': future_date.dayofweek,
                'month': future_date.month,
                'lag_1': recent_df['incident_count'].iloc[-1],
                'lag_7': recent_df['incident_count'].iloc[-7] if len(recent_df) >= 7 else recent_df['incident_count'].mean(),
                'lag_30': recent_df['incident_count'].iloc[-30] if len(recent_df) >= 30 else recent_df['incident_count'].mean(),
                'rolling_avg_7': recent_df['incident_count'].tail(7).mean(),
                'rolling_avg_14': recent_df['incident_count'].tail(14).mean(),
                'rolling_avg_30': recent_df['incident_count'].tail(30).mean(),
                'trend': (future_date - df['timestamp'].min()).days
            }

            X = np.array([list(features.values())])

            # Predict
            prediction = self.model.predict(X)[0]

            # Calculate confidence interval using ensemble predictions
            tree_predictions = np.array([tree.predict(X)[0] for tree in self.model.estimators_])
            std = np.std(tree_predictions)

            # Z-score for confidence level (1.96 for 95%)
            z_score = 1.96 if confidence_level == 0.95 else 2.576  # 99%
            margin = z_score * std

            predictions.append({
                "date": future_date.isoformat(),
                "predicted_count": max(0, int(prediction)),  # Can't be negative
                "confidence_lower": max(0, int(prediction - margin)),
                "confidence_upper": int(prediction + margin),
                "confidence_level": confidence_level
            })

            # Add prediction to DataFrame for next iteration
            new_row = pd.DataFrame([{
                'timestamp': future_date,
                'incident_count': prediction,
                **features
            }])
            df = pd.concat([df, new_row], ignore_index=True)

        duration = (time.perf_counter() - start_time) * 1000

        logger.info(
            "Forecast generated: days=%d, duration=%.2fms",
            days_ahead,
            duration
        )

        # Verify performance target
        if duration > 500:
            logger.warning("Forecast exceeded 500ms target: %.2fms", duration)

        return {
            "forecast": predictions,
            "model_metrics": self.model_metrics,
            "feature_importance": self.feature_importance,
            "prediction_time_ms": duration
        }

    def save_model(self, filepath: str) -> None:
        """Save trained model to disk."""
        if not self.is_trained:
            raise ValueError("Cannot save untrained model")

        with open(filepath, 'wb') as f:
            pickle.dump({
                'model': self.model,
                'feature_importance': self.feature_importance,
                'model_metrics': self.model_metrics
            }, f)

        logger.info("Model saved to %s", filepath)

    def load_model(self, filepath: str) -> None:
        """Load trained model from disk."""
        with open(filepath, 'rb') as f:
            data = pickle.load(f)

        self.model = data['model']
        self.feature_importance = data['feature_importance']
        self.model_metrics = data['model_metrics']
        self.is_trained = True

        logger.info("Model loaded from %s", filepath)


# Global forecaster instance
_forecaster: Optional[IncidentForecaster] = None


def get_forecaster() -> IncidentForecaster:
    """Get or create global forecaster instance."""
    global _forecaster
    if _forecaster is None:
        _forecaster = IncidentForecaster()
    return _forecaster
