"""Time-series forecasting for capacity planning and resource management."""
import numpy as np
import pandas as pd
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Optional, Any
from sklearn.ensemble import RandomForestRegressor

from src.observability.logging import get_logger
from src.observability.metrics import metrics

logger = get_logger(__name__)


class Forecaster:
    """Time-series forecasting using Random Forest with feature engineering."""

    def __init__(
        self,
        n_estimators: int = 100,
        max_depth: int = 10,
        min_samples_split: int = 5,
    ) -> None:
        """Initialize forecaster.

        Args:
            n_estimators: Number of trees in random forest
            max_depth: Maximum depth of trees
            min_samples_split: Minimum samples required to split node
        """
        self.n_estimators = n_estimators
        self.max_depth = max_depth
        self.min_samples_split = min_samples_split
        self.model: Optional[RandomForestRegressor] = None
        self.feature_names: List[str] = []
        
        logger.info(
            "Initialized Forecaster",
            extra={
                "n_estimators": n_estimators,
                "max_depth": max_depth,
            },
        )

    def _engineer_features(
        self,
        df: pd.DataFrame,
        lag_features: List[int] = [1, 2, 3, 6, 12, 24],
        rolling_windows: List[int] = [3, 6, 12, 24],
    ) -> pd.DataFrame:
        """Create features from time series data.

        Args:
            df: DataFrame with timestamp and value columns
            lag_features: List of lag periods to create
            rolling_windows: List of rolling window sizes

        Returns:
            DataFrame with engineered features
        """
        df = df.copy()
        
        # Time-based features
        df["hour"] = df["timestamp"].dt.hour
        df["day_of_week"] = df["timestamp"].dt.dayofweek
        df["is_weekend"] = (df["day_of_week"] >= 5).astype(int)
        
        # Lag features
        for lag in lag_features:
            df[f"lag_{lag}"] = df["value"].shift(lag)
        
        # Rolling statistics
        for window in rolling_windows:
            df[f"rolling_mean_{window}"] = df["value"].rolling(window=window, min_periods=1).mean()
            df[f"rolling_std_{window}"] = df["value"].rolling(window=window, min_periods=1).std()
            df[f"rolling_min_{window}"] = df["value"].rolling(window=window, min_periods=1).min()
            df[f"rolling_max_{window}"] = df["value"].rolling(window=window, min_periods=1).max()
        
        # Rate of change
        df["value_diff"] = df["value"].diff()
        df["value_pct_change"] = df["value"].pct_change()
        
        # Fill NaN values
        df = df.bfill().fillna(0)
        
        return df

    def train(
        self,
        historical_data: List[Tuple[datetime, float]],
        target_hours_ahead: int = 24,
    ) -> Dict[str, Any]:
        """Train forecasting model on historical data.

        Args:
            historical_data: List of (timestamp, value) tuples
            target_hours_ahead: Hours ahead to forecast

        Returns:
            Training results and metrics
        """
        metrics.increment("forecaster.training_runs")
        
        try:
            if len(historical_data) < 48:
                logger.warning(
                    "Insufficient data for training",
                    extra={"data_points": len(historical_data)},
                )
                return {
                    "success": False,
                    "error": "Insufficient data (minimum 48 points required)",
                }

            # Convert to DataFrame
            df = pd.DataFrame(historical_data, columns=["timestamp", "value"])
            df = df.sort_values("timestamp")
            
            # Engineer features
            df = self._engineer_features(df)
            
            # Create target variable (value N hours ahead)
            df["target"] = df["value"].shift(-target_hours_ahead)
            
            # Remove rows with missing target
            df = df.dropna(subset=["target"])
            
            if len(df) < 24:
                return {
                    "success": False,
                    "error": "Insufficient data after feature engineering",
                }

            # Prepare features and target
            feature_cols = [col for col in df.columns if col not in ["timestamp", "value", "target"]]
            X = df[feature_cols].values
            y = df["target"].values
            
            # Train model
            self.model = RandomForestRegressor(
                n_estimators=self.n_estimators,
                max_depth=self.max_depth,
                min_samples_split=self.min_samples_split,
                random_state=42,
                n_jobs=-1,
            )
            
            logger.info("Training forecasting model", extra={"samples": len(X)})
            self.model.fit(X, y)
            self.feature_names = feature_cols
            
            # Calculate training score
            train_score = self.model.score(X, y)
            
            metrics.increment("forecaster.models_trained")
            logger.info(
                "Model trained successfully",
                extra={"train_score": train_score, "features": len(feature_cols)},
            )
            
            return {
                "success": True,
                "train_score": round(train_score, 3),
                "num_features": len(feature_cols),
                "num_samples": len(X),
                "target_hours_ahead": target_hours_ahead,
            }

        except Exception as e:
            logger.error(
                "Error training forecaster",
                extra={"error": str(e)},
                exc_info=True,
            )
            metrics.increment("forecaster.errors")
            return {
                "success": False,
                "error": f"Training failed: {str(e)}",
            }

    def forecast(
        self,
        historical_data: List[Tuple[datetime, float]],
        hours_ahead: int = 24,
    ) -> Dict[str, Any]:
        """Generate forecast for future values.

        Args:
            historical_data: List of (timestamp, value) tuples
            hours_ahead: Number of hours to forecast

        Returns:
            Forecast results with predictions and confidence intervals
        """
        metrics.increment("forecaster.forecasts")
        
        try:
            if self.model is None:
                logger.warning("Model not trained, training now")
                train_result = self.train(historical_data, target_hours_ahead=hours_ahead)
                if not train_result["success"]:
                    return {
                        "success": False,
                        "error": "Model training failed",
                    }

            # Convert to DataFrame
            df = pd.DataFrame(historical_data, columns=["timestamp", "value"])
            df = df.sort_values("timestamp")
            
            # Get most recent data point
            latest_timestamp = df["timestamp"].iloc[-1]
            
            # Engineer features for latest point
            df = self._engineer_features(df)
            latest_features = df[self.feature_names].iloc[-1:].values
            
            # Make prediction
            predicted_value = self.model.predict(latest_features)[0]
            
            # Calculate prediction interval using tree predictions
            tree_predictions = np.array([
                tree.predict(latest_features)[0]
                for tree in self.model.estimators_
            ])
            
            lower_bound = np.percentile(tree_predictions, 5)
            upper_bound = np.percentile(tree_predictions, 95)
            std_dev = np.std(tree_predictions)
            
            # Calculate confidence based on prediction spread
            prediction_range = upper_bound - lower_bound
            current_value = df["value"].iloc[-1]
            confidence = max(0.0, min(1.0, 1.0 - (prediction_range / (current_value + 1e-10))))
            
            forecast_timestamp = latest_timestamp + timedelta(hours=hours_ahead)
            
            metrics.increment("forecaster.predictions_made")
            logger.info(
                "Forecast generated",
                extra={
                    "hours_ahead": hours_ahead,
                    "predicted_value": predicted_value,
                    "confidence": confidence,
                },
            )
            
            return {
                "success": True,
                "current_value": round(float(current_value), 3),
                "current_timestamp": latest_timestamp.isoformat(),
                "forecast_timestamp": forecast_timestamp.isoformat(),
                "forecast_hours_ahead": hours_ahead,
                "predicted_value": round(float(predicted_value), 3),
                "confidence": round(confidence, 3),
                "confidence_interval_95": {
                    "lower": round(float(lower_bound), 3),
                    "upper": round(float(upper_bound), 3),
                },
                "prediction_std_dev": round(float(std_dev), 3),
            }

        except Exception as e:
            logger.error(
                "Error generating forecast",
                extra={"error": str(e)},
                exc_info=True,
            )
            metrics.increment("forecaster.errors")
            return {
                "success": False,
                "error": f"Forecast failed: {str(e)}",
            }

    def capacity_planning(
        self,
        historical_data: List[Tuple[datetime, float]],
        target_threshold: float,
        max_hours_ahead: int = 720,  # 30 days
    ) -> Dict[str, Any]:
        """Predict when a resource will reach a specific threshold.

        Args:
            historical_data: List of (timestamp, value) tuples
            target_threshold: Threshold value to predict (e.g., 95% utilization)
            max_hours_ahead: Maximum hours to look ahead

        Returns:
            Capacity planning prediction
        """
        metrics.increment("forecaster.capacity_planning")
        
        try:
            if len(historical_data) < 48:
                return {
                    "success": False,
                    "error": "Insufficient historical data",
                }

            # Check current value
            current_value = historical_data[-1][1]
            if current_value >= target_threshold:
                return {
                    "success": True,
                    "will_breach": True,
                    "hours_to_breach": 0,
                    "current_value": round(current_value, 3),
                    "target_threshold": target_threshold,
                    "message": "Threshold already breached",
                }

            # Train if needed
            if self.model is None:
                train_result = self.train(historical_data)
                if not train_result["success"]:
                    return {
                        "success": False,
                        "error": "Model training failed",
                    }

            # Check forecasts at different time horizons
            forecast_hours = [1, 6, 12, 24, 48, 72, 168, 336, 720]  # Up to 30 days
            forecast_hours = [h for h in forecast_hours if h <= max_hours_ahead]
            
            breach_hour = None
            forecasts = []
            
            for hours in forecast_hours:
                forecast_result = self.forecast(historical_data, hours_ahead=hours)
                
                if not forecast_result["success"]:
                    continue
                
                forecasts.append({
                    "hours_ahead": hours,
                    "predicted_value": forecast_result["predicted_value"],
                })
                
                if forecast_result["predicted_value"] >= target_threshold and breach_hour is None:
                    breach_hour = hours

            if breach_hour is not None:
                breach_timestamp = datetime.utcnow() + timedelta(hours=breach_hour)
                message = f"Resource predicted to reach {target_threshold} in {breach_hour} hours"
                will_breach = True
            else:
                breach_timestamp = None
                message = f"Resource not expected to reach {target_threshold} within {max_hours_ahead} hours"
                will_breach = False

            return {
                "success": True,
                "will_breach": will_breach,
                "hours_to_breach": breach_hour,
                "breach_timestamp": breach_timestamp.isoformat() if breach_timestamp else None,
                "current_value": round(current_value, 3),
                "target_threshold": target_threshold,
                "forecasts": forecasts,
                "message": message,
            }

        except Exception as e:
            logger.error(
                "Error in capacity planning",
                extra={"error": str(e)},
                exc_info=True,
            )
            metrics.increment("forecaster.errors")
            return {
                "success": False,
                "error": f"Capacity planning failed: {str(e)}",
            }

    def get_feature_importance(self) -> Optional[Dict[str, float]]:
        """Get feature importance scores from trained model.

        Returns:
            Dictionary mapping feature names to importance scores, or None if not trained
        """
        if self.model is None or not self.feature_names:
            return None

        try:
            importances = self.model.feature_importances_
            importance_dict = {
                feature: round(float(importance), 4)
                for feature, importance in zip(self.feature_names, importances)
            }
            
            # Sort by importance
            return dict(sorted(importance_dict.items(), key=lambda x: x[1], reverse=True))

        except Exception as e:
            logger.error(
                "Error getting feature importance",
                extra={"error": str(e)},
                exc_info=True,
            )
            return None
