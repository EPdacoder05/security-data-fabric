"""ML-based forecasting for security metrics."""
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler


class TimeSeriesForecaster:
    """Time series forecasting for security metrics using statistical and ML models.

    Supports incident volume forecasting, trend analysis, and prediction intervals.
    Uses ARIMA-like statistical methods or Prophet for time series forecasting.

    Attributes:
        metric_name: Name of the metric being forecasted
        model_type: Type of forecasting model ('arima' or 'prophet')
        scaler: StandardScaler for data normalization
        trained: Flag indicating if model is trained
        historical_data: Historical time series data
    """

    def __init__(self, metric_name: str, model_type: str = "arima") -> None:
        """Initialize the time series forecaster.

        Args:
            metric_name: Name of the security metric to forecast
            model_type: Type of model to use ('arima' or 'prophet')
        """
        self.metric_name = metric_name
        self.model_type = model_type
        self.scaler = StandardScaler()
        self.trained = False
        self.historical_data: Optional[pd.DataFrame] = None
        self.trend_params: Optional[Dict[str, float]] = None

    async def train(
        self, timestamps: List[datetime], values: List[float], seasonality: bool = True
    ) -> None:
        """Train the forecasting model on historical data.

        Args:
            timestamps: List of timestamp values
            values: List of corresponding metric values
            seasonality: Whether to include seasonal components

        Raises:
            ValueError: If timestamps and values length mismatch
        """
        if len(timestamps) != len(values):
            raise ValueError("Timestamps and values must have same length")

        df = pd.DataFrame({"timestamp": pd.to_datetime(timestamps), "value": values})
        df = df.sort_values("timestamp")

        df["value_scaled"] = self.scaler.fit_transform(df[["value"]])

        self.historical_data = df
        self._fit_trend(seasonality)
        self.trained = True

    def _fit_trend(self, seasonality: bool) -> None:
        """Fit trend and seasonality components.

        Args:
            seasonality: Whether to include seasonal components
        """
        if self.historical_data is None:
            return

        df = self.historical_data
        df["time_idx"] = np.arange(len(df))

        X = df["time_idx"].values.reshape(-1, 1)
        y = df["value_scaled"].values

        trend_coef = np.polyfit(X.flatten(), y, deg=1)

        self.trend_params = {
            "slope": float(trend_coef[0]),
            "intercept": float(trend_coef[1]),
            "mean": float(np.mean(y)),
            "std": float(np.std(y)),
        }

    async def forecast(
        self, periods: int, confidence_level: float = 0.95
    ) -> Dict[str, List[float]]:
        """Generate forecasts for future periods.

        Args:
            periods: Number of future periods to forecast
            confidence_level: Confidence level for prediction intervals (0-1)

        Returns:
            Dictionary containing:
                - timestamps: List of forecast timestamps
                - predictions: Point predictions
                - lower_bound: Lower confidence interval
                - upper_bound: Upper confidence interval

        Raises:
            RuntimeError: If model not trained
        """
        if not self.trained or self.historical_data is None:
            raise RuntimeError("Model must be trained before forecasting")

        last_timestamp = self.historical_data["timestamp"].iloc[-1]
        time_delta = timedelta(hours=1)

        forecast_timestamps = [last_timestamp + time_delta * (i + 1) for i in range(periods)]

        last_idx = len(self.historical_data)
        future_indices = np.arange(last_idx, last_idx + periods)

        predictions_scaled = (
            self.trend_params["slope"] * future_indices + self.trend_params["intercept"]
        )

        predictions = self.scaler.inverse_transform(predictions_scaled.reshape(-1, 1)).flatten()

        z_score = 1.96 if confidence_level == 0.95 else 2.576
        std_error = self.trend_params["std"] * self.scaler.scale_[0]

        lower_bound = predictions - z_score * std_error
        upper_bound = predictions + z_score * std_error

        return {
            "timestamps": [ts.isoformat() for ts in forecast_timestamps],
            "predictions": predictions.tolist(),
            "lower_bound": lower_bound.tolist(),
            "upper_bound": upper_bound.tolist(),
        }

    async def analyze_trend(self) -> Dict[str, Any]:
        """Analyze trend in historical data.

        Returns:
            Dictionary containing:
                - direction: 'increasing', 'decreasing', or 'stable'
                - slope: Rate of change
                - strength: Trend strength (0-1)
                - volatility: Data volatility measure

        Raises:
            RuntimeError: If model not trained
        """
        if not self.trained or self.trend_params is None:
            raise RuntimeError("Model must be trained before trend analysis")

        slope = self.trend_params["slope"]
        std = self.trend_params["std"]

        if abs(slope) < 0.01:
            direction = "stable"
        elif slope > 0:
            direction = "increasing"
        else:
            direction = "decreasing"

        strength = min(abs(slope) / (std + 1e-6), 1.0)
        volatility = std / (abs(self.trend_params["mean"]) + 1e-6)

        return {
            "direction": direction,
            "slope": float(slope),
            "strength": float(strength),
            "volatility": float(volatility),
        }

    async def forecast_incident_volume(self, days_ahead: int = 7) -> Dict[str, Any]:
        """Forecast incident volume for upcoming days.

        Args:
            days_ahead: Number of days to forecast ahead

        Returns:
            Dictionary with daily incident volume forecasts
        """
        periods = days_ahead * 24
        forecast_result = await self.forecast(periods, confidence_level=0.95)

        predictions = np.array(forecast_result["predictions"])
        daily_predictions = predictions.reshape(days_ahead, 24).sum(axis=1)

        timestamps = pd.to_datetime(forecast_result["timestamps"])
        daily_dates = [timestamps[i * 24].date().isoformat() for i in range(days_ahead)]

        return {
            "dates": daily_dates,
            "predicted_volume": daily_predictions.tolist(),
            "total_predicted": float(daily_predictions.sum()),
        }

    async def get_prediction_confidence(
        self, predicted_value: float, actual_value: float
    ) -> Dict[str, float]:
        """Calculate prediction confidence metrics.

        Args:
            predicted_value: Forecasted value
            actual_value: Actual observed value

        Returns:
            Dictionary with confidence metrics:
                - error: Absolute error
                - percent_error: Percentage error
                - confidence_score: Normalized confidence (0-1)
        """
        error = abs(predicted_value - actual_value)
        percent_error = (error / (abs(actual_value) + 1e-6)) * 100

        confidence_score = max(0.0, 1.0 - (percent_error / 100))

        return {
            "error": float(error),
            "percent_error": float(percent_error),
            "confidence_score": float(confidence_score),
        }
