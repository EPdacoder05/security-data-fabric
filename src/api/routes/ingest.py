"""
Manual data ingestion endpoints for Security Data Fabric API.
Allows manual event ingestion for testing and external integrations.
"""
import logging
from typing import Dict, Any, Optional
from datetime import datetime
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.dependencies import get_database_session
from src.database.models import RawEvent, EventSeverity
from src.silver.normalizer import EventNormalizer
from src.silver.enricher import EventEnricher
from src.config.settings import settings

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/ingest", tags=["ingest"])


# Pydantic models
class IngestEventRequest(BaseModel):
    """Request model for event ingestion."""
    event_type: str = Field(..., min_length=1, max_length=100)
    source_id: Optional[str] = Field(None, max_length=255)
    data: Dict[str, Any] = Field(..., description="Event payload data")
    schema_version: str = Field(default="1.0", max_length=20)


class IngestResponse(BaseModel):
    """Response model for ingestion."""
    status: str
    message: str
    event_id: str
    raw_event_id: str
    source: str
    timestamp: datetime


@router.post("/{source}", response_model=IngestResponse, status_code=status.HTTP_202_ACCEPTED)
async def ingest_event(
    source: str,
    request: IngestEventRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_database_session)
) -> IngestResponse:
    """
    Manually ingest an event from a specified source.
    
    This endpoint accepts raw event data and processes it through the
    bronze → silver pipeline (normalization and enrichment).
    
    **Supported sources:**
    - dynatrace
    - splunk
    - servicenow
    - pagerduty
    - github
    - custom
    
    **Parameters:**
    - **source**: Event source system
    - **event_type**: Type of event (e.g., "alert", "metric", "log")
    - **source_id**: Optional original event ID from source system
    - **data**: Event payload (flexible JSON structure)
    - **schema_version**: Schema version (default: "1.0")
    
    **Example payload for Dynatrace:**
    ```json
    {
        "event_type": "problem",
        "source_id": "PROB-12345",
        "data": {
            "title": "High CPU usage",
            "severity": "CRITICAL",
            "entity": {
                "id": "HOST-ABCD1234",
                "type": "HOST",
                "name": "prod-app-01"
            },
            "timestamp": "2024-02-07T10:30:00Z"
        }
    }
    ```
    
    **Example payload for Splunk:**
    ```json
    {
        "event_type": "log_error",
        "data": {
            "message": "Database connection failed",
            "severity": "ERROR",
            "service": "payment-api",
            "timestamp": "2024-02-07T10:30:00Z"
        }
    }
    ```
    """
    # Validate source
    valid_sources = [
        "dynatrace", "splunk", "servicenow", "pagerduty", 
        "github", "custom", "prometheus", "cloudwatch"
    ]
    
    if source.lower() not in valid_sources:
        logger.warning(f"Unknown source: {source}")
        # Allow it but log warning - be permissive for extensibility
    
    try:
        # Create raw event (Bronze layer)
        raw_event = RawEvent(
            source=source.lower(),
            source_id=request.source_id,
            event_type=request.event_type,
            raw_data=request.data,
            schema_version=request.schema_version,
            ingested_at=datetime.utcnow()
        )
        
        db.add(raw_event)
        await db.commit()
        await db.refresh(raw_event)
        
        logger.info(
            f"Raw event ingested: source={source}, "
            f"type={request.event_type}, id={raw_event.id}"
        )
        
        # Schedule background processing (normalization + enrichment)
        async def process_event():
            """Background task for event processing."""
            try:
                # Normalize event (Bronze → Silver)
                normalizer = EventNormalizer(db)
                normalized_event = await normalizer.normalize_event(raw_event)
                
                if normalized_event:
                    logger.info(
                        f"Event normalized: raw_id={raw_event.id}, "
                        f"normalized_id={normalized_event.id}"
                    )
                    
                    # Enrich event
                    enricher = EventEnricher(db)
                    await enricher.enrich_event(normalized_event)
                    
                    logger.info(f"Event enriched: id={normalized_event.id}")
                else:
                    logger.warning(f"Event normalization failed: raw_id={raw_event.id}")
                    
            except Exception as e:
                logger.error(
                    f"Event processing failed: raw_id={raw_event.id}, error={e}",
                    exc_info=True
                )
        
        background_tasks.add_task(process_event)
        
        return IngestResponse(
            status="accepted",
            message=f"Event accepted for processing from {source}",
            event_id=str(raw_event.id),
            raw_event_id=str(raw_event.id),
            source=source.lower(),
            timestamp=datetime.utcnow()
        )
        
    except Exception as e:
        logger.error(f"Event ingestion failed: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Ingestion failed: {str(e)}"
        )


@router.post("/{source}/batch", status_code=status.HTTP_202_ACCEPTED)
async def ingest_events_batch(
    source: str,
    events: list[IngestEventRequest],
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_database_session)
) -> Dict[str, Any]:
    """
    Ingest multiple events in a batch.
    
    Accepts multiple events and processes them asynchronously.
    More efficient than individual requests for bulk ingestion.
    
    **Parameters:**
    - **source**: Event source system
    - **events**: List of event payloads (max 100 per batch)
    
    **Returns:**
    - Batch processing status and count
    """
    # Limit batch size
    max_batch_size = 100
    if len(events) > max_batch_size:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Batch size exceeds maximum of {max_batch_size}"
        )
    
    try:
        raw_event_ids = []
        
        # Create all raw events
        for event_request in events:
            raw_event = RawEvent(
                source=source.lower(),
                source_id=event_request.source_id,
                event_type=event_request.event_type,
                raw_data=event_request.data,
                schema_version=event_request.schema_version,
                ingested_at=datetime.utcnow()
            )
            db.add(raw_event)
            raw_event_ids.append(raw_event.id)
        
        await db.commit()
        
        logger.info(
            f"Batch ingested: source={source}, count={len(events)}"
        )
        
        # Schedule background processing
        async def process_batch():
            """Background task for batch processing."""
            try:
                normalizer = EventNormalizer(db)
                enricher = EventEnricher(db)
                
                for raw_id in raw_event_ids:
                    try:
                        # Get raw event
                        raw_event = await db.get(RawEvent, raw_id)
                        if raw_event:
                            # Normalize
                            normalized = await normalizer.normalize_event(raw_event)
                            if normalized:
                                # Enrich
                                await enricher.enrich_event(normalized)
                    except Exception as e:
                        logger.error(f"Batch item processing failed: {e}")
                        continue
                
                logger.info(f"Batch processing completed: {len(raw_event_ids)} events")
                
            except Exception as e:
                logger.error(f"Batch processing failed: {e}", exc_info=True)
        
        background_tasks.add_task(process_batch)
        
        return {
            "status": "accepted",
            "message": f"Batch of {len(events)} events accepted for processing",
            "source": source.lower(),
            "event_count": len(events),
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Batch ingestion failed: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Batch ingestion failed: {str(e)}"
        )
