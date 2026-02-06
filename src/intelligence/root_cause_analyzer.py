"""Root cause analysis for correlated events."""
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, field
from collections import defaultdict

from src.processing.schema import NormalizedEventSchema
from src.intelligence.correlator import CorrelationResult
from src.observability import get_logger

logger = get_logger(__name__)


@dataclass
class RootCauseCandidate:
    """Candidate root cause with scoring."""

    event_id: str
    event_type: str
    event_title: str
    timestamp: datetime
    source: str
    confidence: float
    reasoning: List[str] = field(default_factory=list)
    contributing_factors: Dict[str, Any] = field(default_factory=dict)


class RootCauseAnalyzer:
    """Analyzes correlated events to identify probable root cause."""

    def __init__(self) -> None:
        """Initialize root cause analyzer."""
        # Historical patterns (in production, loaded from database)
        self.historical_patterns: Dict[str, int] = defaultdict(int)
        logger.info("Initialized root cause analyzer")

    def analyze(
        self,
        events: List[NormalizedEventSchema],
        correlations: List[CorrelationResult],
    ) -> Dict[str, Any]:
        """Analyze events and correlations to identify root cause.

        Args:
            events: List of normalized events
            correlations: List of correlation results

        Returns:
            Root cause analysis with ranked candidates
        """
        if not events:
            return {
                "probable_cause": None,
                "confidence": 0.0,
                "candidates": [],
            }

        # Build event lookup
        event_map = {str(event.id): event for event in events if event.id}

        # Score each event as potential root cause
        candidates = []
        for event in events:
            if not event.id:
                continue

            candidate = self._score_event_as_root_cause(
                event, events, correlations, event_map
            )
            if candidate:
                candidates.append(candidate)

        # Sort by confidence
        candidates.sort(key=lambda c: c.confidence, reverse=True)

        # Build result
        result = {
            "probable_cause": None,
            "confidence": 0.0,
            "candidates": [],
        }

        if candidates:
            top_candidate = candidates[0]
            result["probable_cause"] = top_candidate.event_title
            result["confidence"] = top_candidate.confidence
            result["root_cause_event_id"] = top_candidate.event_id
            result["timestamp"] = top_candidate.timestamp.isoformat()
            result["reasoning"] = top_candidate.reasoning

            # Include top candidates
            result["candidates"] = [
                {
                    "event_id": c.event_id,
                    "event_type": c.event_type,
                    "title": c.event_title,
                    "timestamp": c.timestamp.isoformat(),
                    "source": c.source,
                    "confidence": c.confidence,
                    "reasoning": c.reasoning,
                }
                for c in candidates[:5]  # Top 5 candidates
            ]

        logger.info(
            f"Root cause analysis complete: {len(candidates)} candidates",
            extra={
                "candidate_count": len(candidates),
                "top_confidence": result["confidence"],
            },
        )

        return result

    def _score_event_as_root_cause(
        self,
        event: NormalizedEventSchema,
        all_events: List[NormalizedEventSchema],
        correlations: List[CorrelationResult],
        event_map: Dict[str, NormalizedEventSchema],
    ) -> Optional[RootCauseCandidate]:
        """Score an event as potential root cause.

        Args:
            event: Event to score
            all_events: All events in the incident
            correlations: All correlations
            event_map: Map of event IDs to events

        Returns:
            Root cause candidate if viable
        """
        score = 0.0
        reasoning = []
        factors = {}

        event_id = str(event.id)

        # Factor 1: Temporal proximity (earlier events more likely root cause)
        temporal_score = self._score_temporal_proximity(event, all_events)
        score += temporal_score * 0.3
        if temporal_score > 0.7:
            reasoning.append(f"Occurred early in incident timeline (score: {temporal_score:.2f})")
        factors["temporal_score"] = temporal_score

        # Factor 2: Event type (some types more likely to be root cause)
        type_score = self._score_event_type(event)
        score += type_score * 0.25
        if type_score > 0.7:
            reasoning.append(f"Event type '{event.event_type}' commonly causes incidents")
        factors["type_score"] = type_score

        # Factor 3: Correlation count (events that correlate with many others)
        correlation_score = self._score_correlations(event_id, correlations)
        score += correlation_score * 0.25
        if correlation_score > 0.5:
            corr_count = sum(
                1 for c in correlations
                if c.primary_event_id == event_id or c.correlated_event_id == event_id
            )
            reasoning.append(f"Correlated with {corr_count} other events")
        factors["correlation_score"] = correlation_score

        # Factor 4: Severity (higher severity more likely)
        severity_score = event.severity / 5.0
        score += severity_score * 0.1
        factors["severity_score"] = severity_score

        # Factor 5: Historical patterns
        historical_score = self._score_historical_pattern(event)
        score += historical_score * 0.1
        if historical_score > 0.5:
            reasoning.append("Similar pattern seen in historical incidents")
        factors["historical_score"] = historical_score

        # Normalize score to 0-1
        confidence = min(score, 1.0)

        # Only return if confidence above threshold
        if confidence < 0.3:
            return None

        # Add source-specific reasoning
        if event.source == "github" and event.event_type == "deployment":
            reasoning.append("Deployment changes often introduce issues")
        elif event.source == "github" and event.event_type in ["push", "pr_merge"]:
            reasoning.append("Code changes can introduce bugs")
        elif event.event_type == "config_change":
            reasoning.append("Configuration changes are common root causes")

        return RootCauseCandidate(
            event_id=event_id,
            event_type=event.event_type,
            event_title=event.title,
            timestamp=event.timestamp,
            source=event.source,
            confidence=round(confidence, 3),
            reasoning=reasoning,
            contributing_factors=factors,
        )

    def _score_temporal_proximity(
        self, event: NormalizedEventSchema, all_events: List[NormalizedEventSchema]
    ) -> float:
        """Score based on temporal proximity (earlier = higher score).

        Args:
            event: Event to score
            all_events: All events

        Returns:
            Temporal proximity score (0-1)
        """
        if not all_events:
            return 0.5

        # Sort events by timestamp
        sorted_events = sorted(all_events, key=lambda e: e.timestamp)

        # Find position of this event
        try:
            position = sorted_events.index(event)
        except ValueError:
            return 0.5

        # Score: earlier events get higher scores
        # First event gets 1.0, last event gets 0.1
        if len(sorted_events) == 1:
            return 1.0

        score = 1.0 - (position / (len(sorted_events) - 1)) * 0.9
        return score

    def _score_event_type(self, event: NormalizedEventSchema) -> float:
        """Score based on event type likelihood to be root cause.

        Args:
            event: Event to score

        Returns:
            Event type score (0-1)
        """
        # Event types ranked by likelihood to be root cause
        type_scores = {
            "deployment": 0.9,  # Deployments commonly cause issues
            "config_change": 0.85,  # Config changes often problematic
            "push": 0.75,  # Code changes can introduce bugs
            "pr_merge": 0.75,  # Merged PRs can introduce issues
            "infrastructure": 0.7,  # Infrastructure changes
            "metric": 0.4,  # Metrics are usually symptoms
            "alert": 0.3,  # Alerts are symptoms
            "incident": 0.2,  # Incidents are effects, not causes
        }

        return type_scores.get(event.event_type, 0.5)

    def _score_correlations(
        self, event_id: str, correlations: List[CorrelationResult]
    ) -> float:
        """Score based on number and quality of correlations.

        Args:
            event_id: Event ID to score
            correlations: All correlations

        Returns:
            Correlation score (0-1)
        """
        # Count correlations where this event is the primary (causal) event
        primary_count = sum(
            1 for c in correlations if c.primary_event_id == event_id
        )

        # Count all correlations involving this event
        total_count = sum(
            1
            for c in correlations
            if c.primary_event_id == event_id or c.correlated_event_id == event_id
        )

        if total_count == 0:
            return 0.0

        # Weight primary correlations more heavily
        score = (primary_count * 0.7) + (total_count * 0.3)

        # Normalize (assume max 5 correlations for full score)
        normalized_score = min(score / 5.0, 1.0)

        return normalized_score

    def _score_historical_pattern(self, event: NormalizedEventSchema) -> float:
        """Score based on historical patterns.

        Args:
            event: Event to score

        Returns:
            Historical pattern score (0-1)
        """
        # Create pattern key
        pattern_key = f"{event.source}:{event.event_type}"

        # Check historical frequency
        frequency = self.historical_patterns.get(pattern_key, 0)

        # Normalize (assume 10 occurrences = full confidence)
        score = min(frequency / 10.0, 1.0)

        return score

    def record_root_cause(
        self, event: NormalizedEventSchema, was_root_cause: bool = True
    ) -> None:
        """Record root cause for historical learning.

        Args:
            event: Event that was determined to be root cause
            was_root_cause: Whether this was confirmed as root cause
        """
        if was_root_cause:
            pattern_key = f"{event.source}:{event.event_type}"
            self.historical_patterns[pattern_key] += 1
            logger.info(
                f"Recorded root cause pattern: {pattern_key}",
                extra={"pattern": pattern_key, "count": self.historical_patterns[pattern_key]},
            )

    def get_root_cause_summary(self, analysis: Dict[str, Any]) -> str:
        """Get human-readable summary of root cause analysis.

        Args:
            analysis: Root cause analysis result

        Returns:
            Human-readable summary
        """
        if not analysis.get("probable_cause"):
            return "Root cause could not be determined."

        lines = []
        lines.append(f"Probable Root Cause: {analysis['probable_cause']}")
        lines.append(f"Confidence: {analysis['confidence']:.0%}")

        if reasoning := analysis.get("reasoning"):
            lines.append("\nReasoning:")
            for reason in reasoning:
                lines.append(f"  • {reason}")

        if candidates := analysis.get("candidates"):
            if len(candidates) > 1:
                lines.append(f"\nOther Candidates ({len(candidates) - 1}):")
                for candidate in candidates[1:4]:  # Show up to 3 other candidates
                    lines.append(
                        f"  • {candidate['title']} "
                        f"(confidence: {candidate['confidence']:.0%})"
                    )

        return "\n".join(lines)
