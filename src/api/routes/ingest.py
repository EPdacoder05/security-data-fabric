"""Data ingestion endpoints."""
from typing import Any, Dict
from datetime import datetime, UTC
from fastapi import APIRouter, Depends, HTTPException, Request, status, Header
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from src.database import get_db, models
from src.api.dependencies import require_authenticated_user, CurrentUser
from src.ingestion import GitHubWebhookConnector
from src.observability import get_logger

logger = get_logger(__name__)
router = APIRouter(prefix="/ingest", tags=["ingestion"])


class IngestEventRequest(BaseModel):
    """Manual event ingestion request."""

    source_id: str
    data: Dict[str, Any]


class IngestEventResponse(BaseModel):
    """Event ingestion response."""

    event_id: str
    source: str
    ingested_at: datetime
    message: str


@router.post(
    "/{source}",
    response_model=IngestEventResponse,
    status_code=status.HTTP_201_CREATED,
)
async def ingest_event(
    source: str,
    request: IngestEventRequest,
    db: AsyncSession = Depends(get_db),
    current_user: CurrentUser = Depends(require_authenticated_user),
) -> IngestEventResponse:
    """Manual event ingestion endpoint.
    
    Args:
        source: Event source (e.g., 'github', 'splunk', 'dynatrace')
        request: Event data
        db: Database session
        current_user: Authenticated user
        
    Returns:
        Ingestion result
    """
    logger.info(
        f"Manual event ingestion",
        extra={
            "source": source,
            "source_id": request.source_id,
            "user": current_user.username,
        },
    )
    
    # Create raw event
    raw_event = models.RawEvent(
        source=source,
        source_id=request.source_id,
        raw_data=request.data,
        ingested_at=datetime.now(UTC),
        processed=False,
    )
    
    db.add(raw_event)
    await db.commit()
    await db.refresh(raw_event)
    
    logger.info(
        f"Event ingested successfully",
        extra={"event_id": str(raw_event.id), "source": source},
    )
    
    return IngestEventResponse(
        event_id=str(raw_event.id),
        source=source,
        ingested_at=raw_event.ingested_at,
        message="Event ingested successfully",
    )


@router.post(
    "/github/webhook",
    status_code=status.HTTP_200_OK,
)
async def github_webhook(
    request: Request,
    db: AsyncSession = Depends(get_db),
    x_github_event: str = Header(None),
    x_hub_signature_256: str = Header(None),
) -> Dict[str, str]:
    """GitHub webhook receiver endpoint.
    
    Args:
        request: FastAPI request
        db: Database session
        x_github_event: GitHub event type header
        x_hub_signature_256: GitHub signature header
        
    Returns:
        Acknowledgment response
    """
    if not x_github_event:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Missing X-GitHub-Event header",
        )
    
    # Get raw body
    body = await request.body()
    
    try:
        # Initialize connector and process webhook
        connector = GitHubWebhookConnector(db)
        
        # Verify signature if configured
        if x_hub_signature_256:
            from src.config import settings
            if settings.github_webhook_secret:
                import hmac
                import hashlib
                
                expected_signature = "sha256=" + hmac.new(
                    settings.github_webhook_secret.encode(),
                    body,
                    hashlib.sha256,
                ).hexdigest()
                
                if not hmac.compare_digest(expected_signature, x_hub_signature_256):
                    logger.warning("GitHub webhook signature verification failed")
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="Invalid signature",
                    )
        
        # Parse and store event
        import json
        payload = json.loads(body)
        
        # Create raw event
        raw_event = models.RawEvent(
            source="github",
            source_id=f"{x_github_event}_{payload.get('repository', {}).get('id', 'unknown')}_{datetime.now(UTC).timestamp()}",
            raw_data={
                "event_type": x_github_event,
                "payload": payload,
            },
            ingested_at=datetime.now(UTC),
            processed=False,
        )
        
        db.add(raw_event)
        await db.commit()
        
        logger.info(
            "GitHub webhook received",
            extra={
                "event_type": x_github_event,
                "event_id": str(raw_event.id),
            },
        )
        
        return {"status": "success", "message": "Webhook received"}
        
    except json.JSONDecodeError:
        logger.error("Failed to parse GitHub webhook payload")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid JSON payload",
        )
    except Exception as e:
        logger.error(f"Error processing GitHub webhook: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to process webhook",
        )
