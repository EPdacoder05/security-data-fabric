"""
Time-series forecasting engine for Security Data Fabric.
Implements Random Forest forecasting with feature engineering for capacity planning.
"""
import logging
import os
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestRegressor
from sklearn.metrics import mean_squared_error, r2_score
import joblib

from src.config.settings import settings

logger = logging.getLogger(__name__)


class Forecaster:
    """
    Time-series forecasting engine using Random Forest.
    
    Supports:
    - Feature engineering (lag features, rolling statistics, temporal features)
    - Model persistence
    - Capacity planning predictions
    - Confidence intervals
    """
    
    def __init__(
        self,
        n_estimators: int = 100,
        max_depth: Optional[int] = 10,
        model_path: Optional[str] = None
    ):
        """
        Initialize forecaster.
        
        Args:
            n_estimators: Number of trees in Random Forest
            max_depth: Maximum tree depth
            model_path: Path to save/load models (uses ml_model_path from settings if None)
        """
        self.n_estimators = n_estimators
        self.max_depth = max_depth
        self.model_path = Path(model_path or settings.ml_model_path)
        self.model: Optional[RandomForestRegressor] = None
        self.feature_names: List[str] = []
        self.trained_on: Optional[datetime] = None
        
        # Ensure model directory exists
        self.model_path.mkdir(parents=True, exist_ok=True)
        
        logger.info(
            f"Forecaster initialized: n_estimators={n_estimators}, "
            f"max_depth={max_depth}, model_path={self.model_path}"
        )
    
    def engineer_features(
        self,
        df: pd.DataFrame,
        value_column: str = "value",
        timestamp_column: str = "timestamp",
        lag_periods: List[int] = [1, 2, 3, 6, 12],
        rolling_windows: List[int] = [3, 6, 12]
    ) -> pd.DataFrame:
        """
        Engineer features from time-series data.
        
        Args:
            df: DataFrame with timestamp and value columns
            value_column: Name of value column
            timestamp_column: Name of timestamp column
            lag_periods: List of lag periods for lag features
            rolling_windows: List of window sizes for rolling statistics
        
        Returns:
            DataFrame with engineered features
        """
        df = df.copy()
        
        # Ensure timestamp is datetime
        if not pd.api.types.is_datetime64_any_dtype(df[timestamp_column]):
            df[timestamp_column] = pd.to_datetime(df[timestamp_column])
        
        # Sort by timestamp
        df = df.sort_values(timestamp_column).reset_index(drop=True)
        
        # Temporal features
        df['hour'] = df[timestamp_column].dt.hour
        df['day_of_week'] = df[timestamp_column].dt.dayofweek
        df['day_of_month'] = df[timestamp_column].dt.day
        df['month'] = df[timestamp_column].dt.month
        df['is_weekend'] = df['day_of_week'].isin([5, 6]).astype(int)
        
        # Time since start (hours)
        df['hours_since_start'] = (
            (df[timestamp_column] - df[timestamp_column].iloc[0]).dt.total_seconds() / 3600
        )
        
        # Lag features
        for lag in lag_periods:
            df[f'lag_{lag}'] = df[value_column].shift(lag)
        
        # Rolling statistics
        for window in rolling_windows:
            df[f'rolling_mean_{window}'] = df[value_column].rolling(window=window).mean()
            df[f'rolling_std_{window}'] = df[value_column].rolling(window=window).std()
            df[f'rolling_min_{window}'] = df[value_column].rolling(window=window).min()
            df[f'rolling_max_{window}'] = df[value_column].rolling(window=window).max()
        
        # Rate of change
        df['rate_of_change'] = df[value_column].diff()
        df['rate_of_change_pct'] = df[value_column].pct_change()
        
        # Exponential moving average
        df['ema_3'] = df[value_column].ewm(span=3).mean()
        df['ema_12'] = df[value_column].ewm(span=12).mean()
        
        logger.debug(f"Engineered {len(df.columns) - 2} features from time-series data")
        
        return df
    
    def train(
        self,
        df: pd.DataFrame,
        value_column: str = "value",
        timestamp_column: str = "timestamp",
        test_size: float = 0.2
    ) -> Dict:
        """
        Train forecasting model on historical data.
        
        Args:
            df: DataFrame with historical data
            value_column: Name of value column to predict
            timestamp_column: Name of timestamp column
            test_size: Fraction of data to use for testing
        
        Returns:
            Dictionary with training metrics
        """
        try:
            # Engineer features
            df_features = self.engineer_features(df, value_column, timestamp_column)
            
            # Drop rows with NaN (from lag/rolling features)
            df_features = df_features.dropna()
            
            if len(df_features) < 10:
                raise ValueError("Insufficient data after feature engineering (minimum 10 rows)")
            
            # Prepare features and target
            exclude_cols = [timestamp_column, value_column]
            feature_cols = [col for col in df_features.columns if col not in exclude_cols]
            
            X = df_features[feature_cols].values
            y = df_features[value_column].values
            
            # Split train/test
            split_idx = int(len(X) * (1 - test_size))
            X_train, X_test = X[:split_idx], X[split_idx:]
            y_train, y_test = y[:split_idx], y[split_idx:]
            
            # Train model
            logger.info(f"Training Random Forest on {len(X_train)} samples")
            
            self.model = RandomForestRegressor(
                n_estimators=self.n_estimators,
                max_depth=self.max_depth,
                random_state=42,
                n_jobs=-1
            )
            self.model.fit(X_train, y_train)
            self.feature_names = feature_cols
            self.trained_on = datetime.now()
            
            # Evaluate
            y_pred_train = self.model.predict(X_train)
            y_pred_test = self.model.predict(X_test)
            
            train_rmse = np.sqrt(mean_squared_error(y_train, y_pred_train))
            test_rmse = np.sqrt(mean_squared_error(y_test, y_pred_test))
            train_r2 = r2_score(y_train, y_pred_train)
            test_r2 = r2_score(y_test, y_pred_test)
            
            metrics = {
                "train_rmse": float(train_rmse),
                "test_rmse": float(test_rmse),
                "train_r2": float(train_r2),
                "test_r2": float(test_r2),
                "n_train_samples": len(X_train),
                "n_test_samples": len(X_test),
                "n_features": len(feature_cols),
                "trained_on": self.trained_on.isoformat()
            }
            
            logger.info(
                f"Model trained: test_rmse={test_rmse:.4f}, "
                f"test_r2={test_r2:.4f}, n_samples={len(X)}"
            )
            
            return metrics
            
        except Exception as e:
            logger.error(f"Error training model: {e}")
            raise
    
    def predict(
        self,
        df: pd.DataFrame,
        n_steps: int = 24,
        value_column: str = "value",
        timestamp_column: str = "timestamp"
    ) -> Dict:
        """
        Make future predictions.
        
        Args:
            df: DataFrame with historical data
            n_steps: Number of steps to predict into the future
            value_column: Name of value column
            timestamp_column: Name of timestamp column
        
        Returns:
            Dictionary with predictions and metadata
        """
        try:
            if self.model is None:
                raise ValueError("Model not trained. Call train() first.")
            
            # Engineer features for historical data
            df_features = self.engineer_features(df, value_column, timestamp_column)
            
            # Keep only rows where all feature columns are not NaN
            feature_cols = [col for col in df_features.columns if col not in [timestamp_column, value_column]]
            df_features = df_features.dropna(subset=feature_cols)
            
            if df_features.empty:
                raise ValueError("No valid data after feature engineering")
            
            # Get last timestamp and value
            last_timestamp = df_features[timestamp_column].iloc[-1]
            last_values = df_features[value_column].values
            
            # Determine time interval
            if len(df_features) >= 2:
                time_diff = df_features[timestamp_column].iloc[-1] - df_features[timestamp_column].iloc[-2]
            else:
                time_diff = timedelta(hours=1)  # Default to 1 hour
            
            # Make predictions iteratively
            predictions = []
            timestamps = []
            confidence_intervals = []
            
            # Create working dataframe for iterative predictions
            working_df = df_features.copy()
            
            for step in range(n_steps):
                # Get the last row's features
                last_row_features = working_df[self.feature_names].iloc[-1:].values
                
                # Predict next value
                pred_value = self.model.predict(last_row_features)[0]
                predictions.append(pred_value)
                
                # Calculate prediction interval using tree predictions
                tree_predictions = np.array([
                    tree.predict(last_row_features)[0]
                    for tree in self.model.estimators_
                ])
                pred_std = np.std(tree_predictions)
                
                # 95% confidence interval
                lower_bound = pred_value - 1.96 * pred_std
                upper_bound = pred_value + 1.96 * pred_std
                confidence_intervals.append((lower_bound, upper_bound))
                
                # Next timestamp
                next_timestamp = last_timestamp + time_diff * (step + 1)
                timestamps.append(next_timestamp)
                
                # Add prediction to working dataframe for next iteration
                new_row = {timestamp_column: next_timestamp, value_column: pred_value}
                new_df = pd.concat([working_df, pd.DataFrame([new_row])], ignore_index=True)
                
                # Re-engineer features with the new data
                new_df = self.engineer_features(new_df, value_column, timestamp_column)
                # Drop rows with NaN in feature columns only
                feature_cols = [col for col in new_df.columns if col not in [timestamp_column, value_column]]
                working_df = new_df.dropna(subset=feature_cols)
                
                # Make sure we have at least one row
                if working_df.empty:
                    logger.warning(f"No valid rows after iteration {step}, stopping predictions")
                    break
            
            result = {
                "predictions": predictions,
                "timestamps": [ts.isoformat() for ts in timestamps],
                "confidence_intervals": [
                    {"lower": float(lower), "upper": float(upper)}
                    for lower, upper in confidence_intervals
                ],
                "n_steps": n_steps,
                "last_known_value": float(last_values[-1]),
                "last_known_timestamp": last_timestamp.isoformat()
            }
            
            logger.info(f"Generated {n_steps} predictions")
            return result
            
        except Exception as e:
            logger.error(f"Error making predictions: {e}")
            raise
    
    def save_model(self, model_name: str) -> str:
        """
        Save trained model to disk.
        
        Args:
            model_name: Name for the model file
        
        Returns:
            Path to saved model
        """
        if self.model is None:
            raise ValueError("No model to save. Train a model first.")
        
        try:
            model_file = self.model_path / f"{model_name}.joblib"
            
            # Save model and metadata
            model_data = {
                "model": self.model,
                "feature_names": self.feature_names,
                "trained_on": self.trained_on,
                "n_estimators": self.n_estimators,
                "max_depth": self.max_depth
            }
            
            joblib.dump(model_data, model_file)
            logger.info(f"Model saved to {model_file}")
            
            return str(model_file)
            
        except Exception as e:
            logger.error(f"Error saving model: {e}")
            raise
    
    def load_model(self, model_name: str) -> None:
        """
        Load trained model from disk.
        
        Args:
            model_name: Name of the model file (without .joblib extension)
        """
        try:
            model_file = self.model_path / f"{model_name}.joblib"
            
            if not model_file.exists():
                raise FileNotFoundError(f"Model file not found: {model_file}")
            
            model_data = joblib.load(model_file)
            
            self.model = model_data["model"]
            self.feature_names = model_data["feature_names"]
            self.trained_on = model_data["trained_on"]
            self.n_estimators = model_data.get("n_estimators", self.n_estimators)
            self.max_depth = model_data.get("max_depth", self.max_depth)
            
            logger.info(
                f"Model loaded from {model_file}, "
                f"trained on {self.trained_on.strftime('%Y-%m-%d %H:%M:%S')}"
            )
            
        except Exception as e:
            logger.error(f"Error loading model: {e}")
            raise
    
    def predict_capacity_exhaustion(
        self,
        df: pd.DataFrame,
        capacity: float,
        value_column: str = "value",
        timestamp_column: str = "timestamp",
        max_horizon: int = 168  # 1 week in hours
    ) -> Dict:
        """
        Predict when a resource will reach capacity.
        
        Args:
            df: Historical data
            capacity: Maximum capacity
            value_column: Value column name
            timestamp_column: Timestamp column name
            max_horizon: Maximum prediction horizon (hours)
        
        Returns:
            Dictionary with capacity exhaustion prediction
        """
        try:
            # Make predictions
            predictions = self.predict(df, n_steps=max_horizon, value_column=value_column, timestamp_column=timestamp_column)
            
            # Find when capacity is exceeded
            pred_values = predictions["predictions"]
            pred_timestamps = predictions["timestamps"]
            
            exhaustion_time = None
            exhaustion_step = None
            
            for i, value in enumerate(pred_values):
                if value >= capacity:
                    exhaustion_time = pred_timestamps[i]
                    exhaustion_step = i
                    break
            
            if exhaustion_time:
                result = {
                    "will_exhaust": True,
                    "exhaustion_time": exhaustion_time,
                    "exhaustion_step": exhaustion_step,
                    "current_value": predictions["last_known_value"],
                    "capacity": capacity,
                    "hours_until_exhaustion": exhaustion_step,
                    "explanation": (
                        f"Capacity {capacity} will be reached in approximately "
                        f"{exhaustion_step} hours at {exhaustion_time}"
                    )
                }
            else:
                max_predicted = max(pred_values)
                result = {
                    "will_exhaust": False,
                    "exhaustion_time": None,
                    "exhaustion_step": None,
                    "current_value": predictions["last_known_value"],
                    "capacity": capacity,
                    "max_predicted_value": max_predicted,
                    "explanation": (
                        f"Capacity {capacity} not expected to be reached in next "
                        f"{max_horizon} hours (max predicted: {max_predicted:.2f})"
                    )
                }
            
            result["predictions"] = predictions
            
            logger.info(f"Capacity exhaustion prediction: {result['explanation']}")
            return result
            
        except Exception as e:
            logger.error(f"Error predicting capacity exhaustion: {e}")
            raise
    
    def get_feature_importance(self) -> Optional[Dict[str, float]]:
        """
        Get feature importance scores.
        
        Returns:
            Dictionary mapping feature names to importance scores
        """
        if self.model is None:
            logger.warning("No trained model, cannot get feature importance")
            return None
        
        importances = self.model.feature_importances_
        
        feature_importance = {
            name: float(importance)
            for name, importance in zip(self.feature_names, importances)
        }
        
        # Sort by importance
        feature_importance = dict(
            sorted(feature_importance.items(), key=lambda x: x[1], reverse=True)
        )
        
        return feature_importance
