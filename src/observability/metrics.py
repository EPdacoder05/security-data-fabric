"""Internal metrics tracking."""
import time
from typing import Dict, Any
from collections import defaultdict
from datetime import datetime


class MetricsCollector:
    """Simple in-memory metrics collector."""

    def __init__(self) -> None:
        """Initialize metrics collector."""
        self.counters: Dict[str, int] = defaultdict(int)
        self.gauges: Dict[str, float] = {}
        self.histograms: Dict[str, list] = defaultdict(list)
        self.timers: Dict[str, float] = {}

    def increment(self, metric: str, value: int = 1) -> None:
        """Increment a counter metric.
        
        Args:
            metric: Metric name
            value: Value to add (default: 1)
        """
        self.counters[metric] += value

    def set_gauge(self, metric: str, value: float) -> None:
        """Set a gauge metric.
        
        Args:
            metric: Metric name
            value: Current value
        """
        self.gauges[metric] = value

    def record_histogram(self, metric: str, value: float) -> None:
        """Record a histogram value.
        
        Args:
            metric: Metric name
            value: Value to record
        """
        self.histograms[metric].append(value)
        # Keep only last 1000 values
        if len(self.histograms[metric]) > 1000:
            self.histograms[metric] = self.histograms[metric][-1000:]

    def start_timer(self, metric: str) -> None:
        """Start a timer for a metric.
        
        Args:
            metric: Metric name
        """
        self.timers[metric] = time.time()

    def stop_timer(self, metric: str) -> float:
        """Stop a timer and record the duration.
        
        Args:
            metric: Metric name
            
        Returns:
            Duration in seconds
        """
        if metric in self.timers:
            duration = time.time() - self.timers[metric]
            self.record_histogram(f"{metric}_duration", duration)
            del self.timers[metric]
            return duration
        return 0.0

    def get_snapshot(self) -> Dict[str, Any]:
        """Get a snapshot of all metrics.
        
        Returns:
            Dictionary containing all current metrics
        """
        snapshot = {
            "timestamp": datetime.utcnow().isoformat(),
            "counters": dict(self.counters),
            "gauges": dict(self.gauges),
            "histograms": {},
        }

        # Calculate histogram statistics
        for metric, values in self.histograms.items():
            if values:
                snapshot["histograms"][metric] = {
                    "count": len(values),
                    "min": min(values),
                    "max": max(values),
                    "avg": sum(values) / len(values),
                }

        return snapshot


# Global metrics collector instance
metrics = MetricsCollector()
