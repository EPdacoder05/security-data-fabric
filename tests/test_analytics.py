"""Comprehensive tests for analytics module."""

from datetime import datetime, timedelta, timezone

import numpy as np
import pandas as pd
import pytest

from src.analytics.anomaly_detector import AnomalyDetector
from src.analytics.compliance_reporter import (
    ComplianceFramework,
    ComplianceReporter,
)
from src.analytics.forecaster import TimeSeriesForecaster
from src.analytics.sla_tracker import SLASeverity, SLAStatus, SLATracker


class TestAnomalyDetector:
    """Tests for AnomalyDetector class."""

    def setup_method(self) -> None:
        """Set up test fixtures."""
        self.detector = AnomalyDetector(contamination=0.1, random_state=42)

    @pytest.mark.asyncio
    async def test_train_with_valid_data(self) -> None:
        """Test training anomaly detector with valid data."""
        # Create sample feature data
        features = pd.DataFrame(
            {
                "login_attempts": [10, 12, 11, 13, 15, 14, 10, 12],
                "failed_logins": [1, 0, 1, 2, 1, 0, 1, 0],
                "data_accessed_mb": [100, 105, 98, 102, 110, 108, 95, 100],
            }
        )

        await self.detector.train(features)

        assert self.detector.trained is True
        assert self.detector.feature_names is not None
        assert len(self.detector.feature_names) == 3

    @pytest.mark.asyncio
    async def test_train_with_empty_data(self) -> None:
        """Test training with empty DataFrame raises error."""
        features = pd.DataFrame()

        with pytest.raises(ValueError, match="Features DataFrame cannot be empty"):
            await self.detector.train(features)

    @pytest.mark.asyncio
    async def test_train_with_specific_columns(self) -> None:
        """Test training with specific feature columns."""
        features = pd.DataFrame(
            {
                "login_attempts": [10, 12, 11, 13],
                "failed_logins": [1, 0, 1, 2],
                "ignore_me": ["a", "b", "c", "d"],
            }
        )

        await self.detector.train(features, feature_columns=["login_attempts", "failed_logins"])

        assert self.detector.feature_names == ["login_attempts", "failed_logins"]

    @pytest.mark.asyncio
    async def test_detect_anomalies(self) -> None:
        """Test anomaly detection on new data."""
        # Train on normal data
        train_features = pd.DataFrame(
            {
                "value1": np.random.normal(100, 10, 100),
                "value2": np.random.normal(50, 5, 100),
            }
        )

        await self.detector.train(train_features)

        # Test with mixed normal and anomalous data
        test_features = pd.DataFrame(
            {
                "value1": [100, 105, 1000, 95],  # 1000 is anomalous
                "value2": [50, 48, 500, 52],  # 500 is anomalous
            }
        )

        predictions = await self.detector.detect(test_features)

        assert isinstance(predictions, dict)
        assert "predictions" in predictions
        assert len(predictions["predictions"]) == 4
        assert predictions["predictions"][2] == -1  # Anomaly detected

    @pytest.mark.asyncio
    async def test_get_anomaly_score(self) -> None:
        """Test getting anomaly scores."""
        # Train detector
        train_features = pd.DataFrame(
            {
                "value": np.random.normal(100, 10, 100),
            }
        )

        await self.detector.train(train_features)

        # Get score for a single data point
        normal_score = await self.detector.get_anomaly_score({"value": 100})
        anomalous_score = await self.detector.get_anomaly_score({"value": 200})

        assert isinstance(normal_score, float)
        assert isinstance(anomalous_score, float)
        assert normal_score > anomalous_score  # Normal should have higher score

    @pytest.mark.asyncio
    async def test_detect_realtime(self) -> None:
        """Test real-time anomaly detection."""
        # Train detector
        train_features = pd.DataFrame(
            {
                "metric1": np.random.normal(50, 5, 100),
                "metric2": np.random.normal(100, 10, 100),
            }
        )

        await self.detector.train(train_features)

        # Test single observation
        observation = {"metric1": 50, "metric2": 100}
        result = await self.detector.detect_realtime(observation)

        assert isinstance(result, dict)
        assert "is_anomaly" in result
        assert isinstance(result["is_anomaly"], bool)


class TestTimeSeriesForecaster:
    """Tests for TimeSeriesForecaster class."""

    def setup_method(self) -> None:
        """Set up test fixtures."""
        self.forecaster = TimeSeriesForecaster(metric_name="incident_count")

    @pytest.mark.asyncio
    async def test_train_with_valid_data(self) -> None:
        """Test training forecaster with valid time series data."""
        # Create sample time series data
        timestamps = [datetime(2024, 1, 1) + timedelta(days=i) for i in range(30)]
        values = [10 + i % 5 + np.random.normal(0, 1) for i in range(30)]

        await self.forecaster.train(timestamps, values)

        assert self.forecaster.trained is True
        assert self.forecaster.historical_data is not None
        assert len(self.forecaster.historical_data) == 30

    @pytest.mark.asyncio
    async def test_train_with_mismatched_lengths(self) -> None:
        """Test training with mismatched timestamp and value lengths."""
        timestamps = [datetime(2024, 1, 1), datetime(2024, 1, 2)]
        values = [10, 20, 30]  # Different length

        with pytest.raises(ValueError, match="Timestamps and values must have same length"):
            await self.forecaster.train(timestamps, values)

    @pytest.mark.asyncio
    async def test_forecast_future(self) -> None:
        """Test forecasting future values."""
        # Train with sample data
        timestamps = [datetime(2024, 1, 1) + timedelta(days=i) for i in range(30)]
        values = [10 + 0.5 * i for i in range(30)]  # Linear trend

        await self.forecaster.train(timestamps, values)

        # Forecast next 7 days
        forecast_periods = 7
        predictions = await self.forecaster.forecast(periods=forecast_periods)

        assert isinstance(predictions, dict)
        assert "predictions" in predictions

    @pytest.mark.asyncio
    async def test_forecast_incident_volume(self) -> None:
        """Test incident volume forecasting."""
        timestamps = [datetime(2024, 1, 1) + timedelta(days=i) for i in range(30)]
        values = [10 + np.random.normal(0, 1) for i in range(30)]

        await self.forecaster.train(timestamps, values)

        result = await self.forecaster.forecast_incident_volume(days_ahead=7)

        assert isinstance(result, dict)

    @pytest.mark.asyncio
    async def test_analyze_trend(self) -> None:
        """Test trend analysis."""
        # Create data with upward trend
        timestamps = [datetime(2024, 1, 1) + timedelta(days=i) for i in range(30)]
        values = [10 + 2 * i for i in range(30)]

        await self.forecaster.train(timestamps, values)

        trend_analysis = await self.forecaster.analyze_trend()

        assert isinstance(trend_analysis, dict)

    @pytest.mark.asyncio
    async def test_get_prediction_confidence(self) -> None:
        """Test getting prediction confidence."""
        timestamps = [datetime(2024, 1, 1) + timedelta(days=i) for i in range(30)]
        values = [10 + np.random.normal(0, 1) for i in range(30)]

        await self.forecaster.train(timestamps, values)

        # Test confidence with predicted and actual values
        confidence = await self.forecaster.get_prediction_confidence(
            predicted_value=10.5, actual_value=10.0
        )

        assert isinstance(confidence, dict)
        assert "error" in confidence
        assert "confidence_score" in confidence


class TestComplianceReporter:
    """Tests for ComplianceReporter class."""

    def setup_method(self) -> None:
        """Set up test fixtures."""
        self.reporter = ComplianceReporter(framework=ComplianceFramework.SOC2)

    def test_initialization_with_framework(self) -> None:
        """Test initialization with different frameworks."""
        reporters = [
            ComplianceReporter(ComplianceFramework.SOC2),
            ComplianceReporter(ComplianceFramework.ISO27001),
            ComplianceReporter(ComplianceFramework.GDPR),
            ComplianceReporter(ComplianceFramework.HIPAA),
            ComplianceReporter(ComplianceFramework.PCI_DSS),
            ComplianceReporter(ComplianceFramework.NIST),
        ]

        for reporter in reporters:
            assert reporter.framework in ComplianceFramework
            assert reporter.controls is not None

    @pytest.mark.asyncio
    async def test_check_compliance(self) -> None:
        """Test checking compliance status."""
        control_id = "CC1.1"
        evidence = {
            "policy_exists": True,
            "training_completed": True,
        }

        result = await self.reporter.check_compliance(control_id, evidence)

        assert isinstance(result, dict)
        assert "status" in result

    @pytest.mark.asyncio
    async def test_generate_compliance_report(self) -> None:
        """Test generating a compliance report."""
        # Provide control statuses
        control_statuses = {
            "CC1.1": ComplianceStatus.COMPLIANT,
            "CC1.2": ComplianceStatus.NON_COMPLIANT,
        }
        report = await self.reporter.generate_compliance_report(control_statuses)

        assert isinstance(report, dict)
        assert "framework" in report

    @pytest.mark.asyncio
    async def test_perform_gap_analysis(self) -> None:
        """Test performing gap analysis."""
        # Provide control statuses for gap analysis
        control_statuses = {
            "CC1.1": ComplianceStatus.COMPLIANT,
            "CC1.2": ComplianceStatus.NON_COMPLIANT,
        }
        gaps = await self.reporter.perform_gap_analysis(control_statuses)

        assert isinstance(gaps, list)

    @pytest.mark.asyncio
    async def test_get_compliance_history(self) -> None:
        """Test getting compliance history."""
        control_id = "CC1.1"
        history = await self.reporter.get_compliance_history(control_id, days=30)

        assert isinstance(history, list)

    @pytest.mark.asyncio
    async def test_track_compliance_over_time(self) -> None:
        """Test tracking compliance over time."""
        control_id = "CC1.1"
        status = ComplianceStatus.COMPLIANT
        
        await self.reporter.track_compliance_over_time(control_id, status)
        
        # Verify tracking was successful (no exception raised)
        assert True


class TestSLATracker:
    """Tests for SLATracker class."""

    def setup_method(self) -> None:
        """Set up test fixtures."""
        self.tracker = SLATracker(warning_threshold=0.8)

    @pytest.mark.asyncio
    async def test_start_tracking_critical(self) -> None:
        """Test starting SLA tracking for critical incident."""
        incident_id = "INC-001"
        severity = SLASeverity.CRITICAL.value

        sla_record = await self.tracker.start_tracking(incident_id, severity)

        assert sla_record["incident_id"] == incident_id
        assert sla_record["severity"] == severity
        assert sla_record["target_response_minutes"] == 15
        assert sla_record["status"] == SLAStatus.PENDING.value

    @pytest.mark.asyncio
    async def test_start_tracking_different_severities(self) -> None:
        """Test SLA tracking for different severity levels."""
        severities = [
            (SLASeverity.CRITICAL, 15),
            (SLASeverity.HIGH, 60),
            (SLASeverity.MEDIUM, 240),
            (SLASeverity.LOW, 1440),
            (SLASeverity.INFORMATIONAL, 2880),
        ]

        for severity, expected_minutes in severities:
            sla_record = await self.tracker.start_tracking(
                f"INC-{severity.value}",
                severity.value,
            )

            assert sla_record["target_response_minutes"] == expected_minutes

    @pytest.mark.asyncio
    async def test_start_tracking_invalid_severity(self) -> None:
        """Test starting tracking with invalid severity."""
        with pytest.raises(ValueError, match="Invalid severity"):
            await self.tracker.start_tracking("INC-001", 99)

    @pytest.mark.asyncio
    async def test_check_sla_status_within_target(self) -> None:
        """Test checking SLA status within target time."""
        incident_id = "INC-001"
        created_at = datetime.now(timezone.utc) - timedelta(minutes=5)

        await self.tracker.start_tracking(incident_id, SLASeverity.CRITICAL.value, created_at)

        status = await self.tracker.check_sla_status(incident_id)

        assert isinstance(status, dict)

    @pytest.mark.asyncio
    async def test_check_sla_status_at_risk(self) -> None:
        """Test checking SLA status at risk."""
        incident_id = "INC-002"
        created_at = datetime.now(timezone.utc) - timedelta(minutes=13)  # 13 of 15 minutes

        await self.tracker.start_tracking(incident_id, SLASeverity.CRITICAL.value, created_at)

        status = await self.tracker.check_sla_status(incident_id)

        assert isinstance(status, dict)

    @pytest.mark.asyncio
    async def test_check_sla_status_breached(self) -> None:
        """Test checking SLA status when breached."""
        incident_id = "INC-003"
        created_at = datetime.now(timezone.utc) - timedelta(minutes=20)  # Exceeds 15 minutes

        await self.tracker.start_tracking(incident_id, SLASeverity.CRITICAL.value, created_at)

        status = await self.tracker.check_sla_status(incident_id)

        assert isinstance(status, dict)

    @pytest.mark.asyncio
    async def test_resolve_incident_within_sla(self) -> None:
        """Test resolving incident within SLA."""
        incident_id = "INC-004"
        created_at = datetime.now(timezone.utc) - timedelta(minutes=5)

        await self.tracker.start_tracking(incident_id, SLASeverity.CRITICAL.value, created_at)

        result = await self.tracker.resolve_incident(incident_id)

        assert isinstance(result, dict)

    @pytest.mark.asyncio
    async def test_resolve_incident_breached_sla(self) -> None:
        """Test resolving incident after SLA breach."""
        incident_id = "INC-005"
        created_at = datetime.now(timezone.utc) - timedelta(minutes=20)

        await self.tracker.start_tracking(incident_id, SLASeverity.CRITICAL.value, created_at)

        result = await self.tracker.resolve_incident(incident_id)

        assert isinstance(result, dict)

    @pytest.mark.asyncio
    async def test_get_sla_metrics(self) -> None:
        """Test getting SLA performance metrics."""
        # Create multiple incidents
        for i in range(5):
            await self.tracker.start_tracking(f"INC-{i}", SLASeverity.HIGH.value)

        metrics = await self.tracker.get_sla_metrics()

        assert isinstance(metrics, dict)

    @pytest.mark.asyncio
    async def test_get_at_risk_incidents(self) -> None:
        """Test getting at-risk SLAs."""
        # Create incident approaching SLA breach
        incident_id = "INC-RISK"
        created_at = datetime.now(timezone.utc) - timedelta(minutes=13)

        await self.tracker.start_tracking(incident_id, SLASeverity.CRITICAL.value, created_at)

        at_risk = await self.tracker.get_at_risk_incidents()

        assert isinstance(at_risk, list)

    @pytest.mark.asyncio
    async def test_detect_breaches(self) -> None:
        """Test detecting breached SLAs."""
        # Create incident that will be breached
        incident_id = "INC-BREACH"
        created_at = datetime.now(timezone.utc) - timedelta(minutes=30)

        await self.tracker.start_tracking(incident_id, SLASeverity.CRITICAL.value, created_at)

        breached = await self.tracker.detect_breaches()

        assert isinstance(breached, list)

    @pytest.mark.asyncio
    async def test_get_incident_sla(self) -> None:
        """Test getting SLA for specific incident."""
        incident_id = "INC-TEST"

        await self.tracker.start_tracking(incident_id, SLASeverity.HIGH.value)

        sla_data = await self.tracker.get_incident_sla(incident_id)

        assert isinstance(sla_data, dict)
