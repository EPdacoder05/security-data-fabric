"""Bronze layer ingestion pipeline for Security Data Fabric.

Validates, ingests, and routes records from any connector into the Bronze layer.
"""

import hashlib
import json
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import uuid4

from src.security.input_validator import InputValidator

logger = logging.getLogger(__name__)


class IngestionStatus(str, Enum):
    """Status of a batch ingestion operation."""

    SUCCESS = "success"
    PARTIAL = "partial"
    FAILED = "failed"


@dataclass
class BronzeRecord:
    """A single record in the Bronze layer."""

    id: str
    source_name: str
    source_id: str
    raw_payload: Dict[str, Any]
    ingestion_timestamp: datetime
    data_hash: str


@dataclass
class QuarantineRecord:
    """A record that failed validation and was quarantined."""

    id: str
    source_name: str
    raw_payload: Dict[str, Any]
    failure_reason: str
    quarantine_timestamp: datetime


@dataclass
class IngestionMetrics:
    """Metrics for a single batch ingestion operation."""

    source_name: str
    batch_id: str
    total_records: int = 0
    successful_records: int = 0
    failed_records: int = 0
    quarantined_records: int = 0
    duplicate_records: int = 0
    status: IngestionStatus = IngestionStatus.SUCCESS
    error_messages: List[str] = field(default_factory=list)
    duration_seconds: float = 0.0
    ingested_at: Optional[datetime] = None


class IngestionPipeline:
    """Bronze layer ingestion pipeline.

    Validates records from any connector and routes them to the Bronze layer.
    Invalid/malicious records are quarantined rather than rejected silently.
    """

    def __init__(self, db_session: Any = None) -> None:
        """Initialize the ingestion pipeline.

        Args:
            db_session: Database session (SQLAlchemy async session or mock)
        """
        self.db = db_session
        self.validator = InputValidator()
        self._bronze_records: List[BronzeRecord] = []
        self._quarantine_records: List[QuarantineRecord] = []
        self._ingestion_metadata: List[Dict[str, Any]] = []

    def _compute_hash(self, payload: Dict[str, Any]) -> str:
        """Compute a deterministic SHA-256 hash of a record payload.

        Args:
            payload: Record payload dictionary

        Returns:
            Hex digest of the payload hash
        """
        canonical = json.dumps(payload, sort_keys=True, default=str)
        return hashlib.sha256(canonical.encode()).hexdigest()

    def _extract_source_id(self, source_name: str, record: Dict[str, Any]) -> str:
        """Extract a source-specific identifier from the record.

        Args:
            source_name: Name of the data source
            record: Record dictionary

        Returns:
            Source identifier string
        """
        id_fields = {
            "servicenow": "number",
            "grafana": "alertname",
            "defender": "incidentId",
            "usatoday": "id",
        }
        id_field = id_fields.get(source_name, "id")
        return str(record.get(id_field, str(uuid4())))

    def _is_duplicate(self, data_hash: str) -> bool:
        """Check if a record with this hash has already been ingested.

        Args:
            data_hash: SHA-256 hash of the record payload

        Returns:
            True if the record is a duplicate
        """
        return any(r.data_hash == data_hash for r in self._bronze_records)

    def _validate_record(self, record: Any) -> Optional[str]:
        """Validate a single record for type and security threats.

        Args:
            record: Record to validate

        Returns:
            Error message if invalid, None if valid
        """
        if not isinstance(record, dict):
            return f"Expected dict, got {type(record).__name__}"

        # Flatten record values to strings for threat scanning
        flat_values = []
        for v in record.values():
            if isinstance(v, str):
                flat_values.append(v)
            elif isinstance(v, list):
                for item in v:
                    if isinstance(item, str):
                        flat_values.append(item)

        for value in flat_values:
            result = self.validator.validate(value)
            if not result.is_valid:
                threat_types = [t.get("type", "unknown") for t in result.threats]
                return f"Security threat detected: {', '.join(threat_types)}"

        return None

    async def ingest_batch(
        self,
        source_name: str,
        records: List[Any],
        batch_id: Optional[str] = None,
    ) -> IngestionMetrics:
        """Ingest a batch of records from a connector into the Bronze layer.

        Args:
            source_name: Name of the data source (e.g., 'servicenow')
            records: List of record dictionaries to ingest
            batch_id: Optional batch identifier for tracking

        Returns:
            IngestionMetrics with counts and status
        """
        batch_id = batch_id or str(uuid4())
        start_time = time.time()
        metrics = IngestionMetrics(
            source_name=source_name,
            batch_id=batch_id,
            total_records=len(records),
            ingested_at=datetime.now(timezone.utc),
        )

        if not records:
            metrics.status = IngestionStatus.SUCCESS
            metrics.duration_seconds = time.time() - start_time
            self._store_metadata(metrics)
            return metrics

        for record in records:
            try:
                # Validate the record
                error = self._validate_record(record)
                if error:
                    self._quarantine(source_name, record, error)
                    metrics.quarantined_records += 1
                    metrics.error_messages.append(error)
                    continue

                # Compute hash for deduplication
                data_hash = self._compute_hash(record)
                if self._is_duplicate(data_hash):
                    metrics.duplicate_records += 1
                    continue

                # Store in bronze layer
                source_id = self._extract_source_id(source_name, record)
                bronze_record = BronzeRecord(
                    id=str(uuid4()),
                    source_name=source_name,
                    source_id=source_id,
                    raw_payload=record,
                    ingestion_timestamp=datetime.now(timezone.utc),
                    data_hash=data_hash,
                )
                self._bronze_records.append(bronze_record)
                metrics.successful_records += 1

                # If real DB session, persist asynchronously
                if self.db is not None:
                    await self._persist_record(bronze_record)

            except Exception as exc:
                metrics.failed_records += 1
                error_msg = f"Failed to process record: {exc}"
                metrics.error_messages.append(error_msg)
                logger.warning(error_msg)

        # Determine overall status
        if metrics.quarantined_records > 0 or metrics.failed_records > 0:
            if metrics.successful_records > 0:
                metrics.status = IngestionStatus.PARTIAL
            else:
                metrics.status = IngestionStatus.FAILED
        else:
            metrics.status = IngestionStatus.SUCCESS

        metrics.duration_seconds = time.time() - start_time
        self._store_metadata(metrics)
        logger.info(
            "Ingested batch %s from %s: %d/%d records successful",
            batch_id,
            source_name,
            metrics.successful_records,
            metrics.total_records,
        )
        return metrics

    def _quarantine(self, source_name: str, record: Any, reason: str) -> None:
        """Move a record to the quarantine store.

        Args:
            source_name: Source that provided the record
            record: The record payload (may not be a dict)
            reason: Why it was quarantined
        """
        quarantine_record = QuarantineRecord(
            id=str(uuid4()),
            source_name=source_name,
            raw_payload=record if isinstance(record, dict) else {"raw": str(record)},
            failure_reason=reason,
            quarantine_timestamp=datetime.now(timezone.utc),
        )
        self._quarantine_records.append(quarantine_record)
        logger.warning("Quarantined record from %s: %s", source_name, reason)

    async def _persist_record(self, record: BronzeRecord) -> None:
        """Persist a bronze record to the database.

        Args:
            record: BronzeRecord to persist
        """
        # In production with a real DB session, execute INSERT here.
        # For testability this is a no-op stub that subclasses/tests can override.
        pass

    def _store_metadata(self, metrics: IngestionMetrics) -> None:
        """Store ingestion batch metadata.

        Args:
            metrics: Metrics from the batch run
        """
        self._ingestion_metadata.append(
            {
                "batch_id": metrics.batch_id,
                "source_name": metrics.source_name,
                "records_ingested": metrics.successful_records,
                "records_failed": metrics.failed_records,
                "records_quarantined": metrics.quarantined_records,
                "status": metrics.status,
                "ingestion_timestamp": metrics.ingested_at,
                "error_log": metrics.error_messages,
            }
        )

    def get_bronze_record_count(self, source_name: Optional[str] = None) -> int:
        """Return the number of bronze records, optionally filtered by source.

        Args:
            source_name: Optional source to filter by

        Returns:
            Count of bronze records
        """
        if source_name:
            return sum(1 for r in self._bronze_records if r.source_name == source_name)
        return len(self._bronze_records)

    def get_quarantine_count(self, source_name: Optional[str] = None) -> int:
        """Return the number of quarantined records.

        Args:
            source_name: Optional source to filter by

        Returns:
            Count of quarantined records
        """
        if source_name:
            return sum(1 for r in self._quarantine_records if r.source_name == source_name)
        return len(self._quarantine_records)

    def health_check(self) -> Dict[str, Any]:
        """Return health status of the ingestion pipeline.

        Returns:
            Dictionary with health status information
        """
        return {
            "status": "healthy",
            "bronze_record_count": self.get_bronze_record_count(),
            "quarantine_count": self.get_quarantine_count(),
            "total_batches": len(self._ingestion_metadata),
        }
