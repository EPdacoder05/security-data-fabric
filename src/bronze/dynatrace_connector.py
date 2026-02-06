"""
Dynatrace REST API connector for Bronze layer ingestion.
Fetches problems, metrics, and entities from Dynatrace API v2.
"""
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
import logging

from src.bronze.base_connector import BaseConnector
from src.config.settings import settings

logger = logging.getLogger(__name__)


class DynatraceConnector(BaseConnector):
    """Connector for Dynatrace API v2."""
    
    def __init__(
        self,
        base_url: Optional[str] = None,
        api_token: Optional[str] = None,
        timeout: float = 30.0,
        max_retries: int = 3,
    ):
        """
        Initialize Dynatrace connector.
        
        Args:
            base_url: Dynatrace environment URL (e.g., https://abc12345.live.dynatrace.com)
            api_token: Dynatrace API token with required permissions
            timeout: Request timeout in seconds
            max_retries: Maximum number of retry attempts
        """
        super().__init__(
            name="Dynatrace",
            base_url=base_url or settings.dynatrace_base_url or "",
            api_key=api_token or settings.dynatrace_api_token,
            timeout=timeout,
            max_retries=max_retries,
        )
        
        if not self.base_url:
            raise ValueError("Dynatrace base_url is required")
        if not self.api_key:
            raise ValueError("Dynatrace api_token is required")
    
    def _get_headers(self) -> Dict[str, str]:
        """Get HTTP headers for Dynatrace API requests."""
        return {
            "Authorization": f"Api-Token {self.api_key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
    
    async def health_check(self) -> bool:
        """
        Check if the Dynatrace API is accessible.
        
        Returns:
            True if healthy, False otherwise
        """
        try:
            # Use the cluster version endpoint for health check
            await self._make_request("GET", "/api/v1/config/clusterversion")
            logger.info(f"{self.name} health check passed")
            return True
        except Exception as e:
            logger.error(f"{self.name} health check failed: {e}")
            return False
    
    async def fetch(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        **kwargs
    ) -> List[Dict[str, Any]]:
        """
        Fetch events from Dynatrace.
        
        Args:
            start_time: Start of time range (default: last hour)
            end_time: End of time range (default: now)
            **kwargs: Additional parameters:
                - entity_selector: Dynatrace entity selector string
                - problem_selector: Problem selector string
                - fetch_problems: Fetch problems (default: True)
                - fetch_events: Fetch events (default: True)
                - fetch_entities: Fetch entities (default: False)
        
        Returns:
            List of raw event dictionaries in Bronze format
        """
        if start_time is None or end_time is None:
            start_time, end_time = self._get_default_time_range()
        
        all_events = []
        
        # Fetch problems
        if kwargs.get("fetch_problems", True):
            problems = await self._fetch_problems(start_time, end_time, kwargs)
            all_events.extend(problems)
        
        # Fetch events
        if kwargs.get("fetch_events", True):
            events = await self._fetch_events(start_time, end_time, kwargs)
            all_events.extend(events)
        
        # Fetch entities (optional, can be heavy)
        if kwargs.get("fetch_entities", False):
            entities = await self._fetch_entities(kwargs)
            all_events.extend(entities)
        
        logger.info(f"Fetched {len(all_events)} events from {self.name}")
        return all_events
    
    async def _fetch_problems(
        self,
        start_time: datetime,
        end_time: datetime,
        params: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Fetch problems from Dynatrace Problems API v2."""
        try:
            # Convert to milliseconds for Dynatrace API
            from_ms = int(start_time.timestamp() * 1000)
            to_ms = int(end_time.timestamp() * 1000)
            
            query_params = {
                "from": from_ms,
                "to": to_ms,
                "pageSize": 500,
            }
            
            if "problem_selector" in params:
                query_params["problemSelector"] = params["problem_selector"]
            
            response = await self._make_request(
                "GET",
                "/api/v2/problems",
                params=query_params
            )
            
            problems = response.get("problems", [])
            return [self._transform_problem(p) for p in problems]
        
        except Exception as e:
            logger.error(f"Failed to fetch problems: {e}")
            return []
    
    async def _fetch_events(
        self,
        start_time: datetime,
        end_time: datetime,
        params: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Fetch events from Dynatrace Events API v2."""
        try:
            from_ms = int(start_time.timestamp() * 1000)
            to_ms = int(end_time.timestamp() * 1000)
            
            query_params = {
                "from": from_ms,
                "to": to_ms,
                "pageSize": 1000,
            }
            
            if "entity_selector" in params:
                query_params["entitySelector"] = params["entity_selector"]
            
            response = await self._make_request(
                "GET",
                "/api/v2/events",
                params=query_params
            )
            
            events = response.get("events", [])
            return [self._transform_event(e) for e in events]
        
        except Exception as e:
            logger.error(f"Failed to fetch events: {e}")
            return []
    
    async def _fetch_entities(self, params: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Fetch entities from Dynatrace Entities API v2."""
        try:
            query_params = {
                "pageSize": 500,
            }
            
            if "entity_selector" in params:
                query_params["entitySelector"] = params["entity_selector"]
            
            response = await self._make_request(
                "GET",
                "/api/v2/entities",
                params=query_params
            )
            
            entities = response.get("entities", [])
            return [self._transform_entity(e) for e in entities]
        
        except Exception as e:
            logger.error(f"Failed to fetch entities: {e}")
            return []
    
    def _transform_problem(self, problem: Dict[str, Any]) -> Dict[str, Any]:
        """Transform Dynatrace problem to Bronze format."""
        return {
            "source": "dynatrace",
            "source_type": "problem",
            "event_id": problem.get("problemId"),
            "timestamp": datetime.fromtimestamp(problem.get("startTime", 0) / 1000).isoformat(),
            "severity": problem.get("severityLevel", "INFO").upper(),
            "title": problem.get("title", ""),
            "description": problem.get("displayId", ""),
            "status": problem.get("status", "OPEN"),
            "impact_level": problem.get("impactLevel", ""),
            "affected_entities": problem.get("affectedEntities", []),
            "root_cause_entity": problem.get("rootCauseEntity", {}),
            "evidence_details": problem.get("evidenceDetails", {}),
            "management_zones": problem.get("managementZones", []),
            "raw_data": problem,
            "ingested_at": datetime.utcnow().isoformat(),
        }
    
    def _transform_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Transform Dynatrace event to Bronze format."""
        return {
            "source": "dynatrace",
            "source_type": "event",
            "event_id": event.get("eventId"),
            "timestamp": datetime.fromtimestamp(event.get("startTime", 0) / 1000).isoformat(),
            "severity": event.get("eventLevel", "INFO").upper(),
            "title": event.get("eventType", ""),
            "description": event.get("title", ""),
            "event_type": event.get("eventType", ""),
            "entity_id": event.get("entityId", {}).get("id", ""),
            "entity_name": event.get("entityId", {}).get("name", ""),
            "properties": event.get("properties", {}),
            "raw_data": event,
            "ingested_at": datetime.utcnow().isoformat(),
        }
    
    def _transform_entity(self, entity: Dict[str, Any]) -> Dict[str, Any]:
        """Transform Dynatrace entity to Bronze format."""
        return {
            "source": "dynatrace",
            "source_type": "entity",
            "event_id": entity.get("entityId"),
            "timestamp": datetime.utcnow().isoformat(),
            "severity": "INFO",
            "title": f"Entity: {entity.get('displayName', '')}",
            "description": entity.get("type", ""),
            "entity_id": entity.get("entityId"),
            "entity_type": entity.get("type"),
            "display_name": entity.get("displayName", ""),
            "properties": entity.get("properties", {}),
            "tags": entity.get("tags", []),
            "management_zones": entity.get("managementZones", []),
            "raw_data": entity,
            "ingested_at": datetime.utcnow().isoformat(),
        }
