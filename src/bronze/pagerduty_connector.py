"""
PagerDuty REST API v2 connector for Bronze layer ingestion.
Fetches incidents, on-call schedules, and related data.
"""
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
import logging

from src.bronze.base_connector import BaseConnector
from src.config.settings import settings

logger = logging.getLogger(__name__)


class PagerDutyConnector(BaseConnector):
    """Connector for PagerDuty REST API v2."""
    
    def __init__(
        self,
        api_key: Optional[str] = None,
        from_email: Optional[str] = None,
        timeout: float = 30.0,
        max_retries: int = 3,
    ):
        """
        Initialize PagerDuty connector.
        
        Args:
            api_key: PagerDuty API key/token
            from_email: Email for audit trail (required for some operations)
            timeout: Request timeout in seconds
            max_retries: Maximum number of retry attempts
        """
        super().__init__(
            name="PagerDuty",
            base_url="https://api.pagerduty.com",
            api_key=api_key or settings.pagerduty_api_key,
            timeout=timeout,
            max_retries=max_retries,
        )
        
        self.from_email = from_email or settings.pagerduty_from_email
        
        if not self.api_key:
            raise ValueError("PagerDuty api_key is required")
    
    def _get_headers(self) -> Dict[str, str]:
        """Get HTTP headers for PagerDuty API requests."""
        headers = {
            "Authorization": f"Token token={self.api_key}",
            "Accept": "application/vnd.pagerduty+json;version=2",
            "Content-Type": "application/json",
        }
        
        if self.from_email:
            headers["From"] = self.from_email
        
        return headers
    
    async def health_check(self) -> bool:
        """
        Check if the PagerDuty API is accessible.
        
        Returns:
            True if healthy, False otherwise
        """
        try:
            # Query current user to verify authentication
            await self._make_request("GET", "/users/me")
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
        Fetch events from PagerDuty.
        
        Args:
            start_time: Start of time range (default: last hour)
            end_time: End of time range (default: now)
            **kwargs: Additional parameters:
                - fetch_incidents: Fetch incidents (default: True)
                - fetch_oncalls: Fetch on-call schedules (default: True)
                - fetch_services: Fetch services (default: False)
                - incident_statuses: List of statuses to filter (e.g., ["triggered", "acknowledged"])
                - team_ids: List of team IDs to filter
                - service_ids: List of service IDs to filter
        
        Returns:
            List of raw event dictionaries in Bronze format
        """
        if start_time is None or end_time is None:
            start_time, end_time = self._get_default_time_range()
        
        all_events = []
        
        # Fetch incidents
        if kwargs.get("fetch_incidents", True):
            incidents = await self._fetch_incidents(start_time, end_time, kwargs)
            all_events.extend(incidents)
        
        # Fetch on-call schedules
        if kwargs.get("fetch_oncalls", True):
            oncalls = await self._fetch_oncalls(start_time, end_time, kwargs)
            all_events.extend(oncalls)
        
        # Fetch services (optional)
        if kwargs.get("fetch_services", False):
            services = await self._fetch_services(kwargs)
            all_events.extend(services)
        
        logger.info(f"Fetched {len(all_events)} events from {self.name}")
        return all_events
    
    async def _fetch_incidents(
        self,
        start_time: datetime,
        end_time: datetime,
        params: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Fetch incidents from PagerDuty."""
        try:
            query_params = {
                "since": start_time.isoformat(),
                "until": end_time.isoformat(),
                "limit": 100,
                "offset": 0,
                "total": "true",
            }
            
            # Filter by statuses
            statuses = params.get("incident_statuses", ["triggered", "acknowledged"])
            query_params["statuses[]"] = statuses
            
            # Filter by team IDs
            if "team_ids" in params:
                query_params["team_ids[]"] = params["team_ids"]
            
            # Filter by service IDs
            if "service_ids" in params:
                query_params["service_ids[]"] = params["service_ids"]
            
            all_incidents = []
            
            # Paginate through results
            while True:
                response = await self._make_request(
                    "GET",
                    "/incidents",
                    params=query_params
                )
                
                incidents = response.get("incidents", [])
                all_incidents.extend(incidents)
                
                # Check if more pages exist
                if not response.get("more", False):
                    break
                
                query_params["offset"] += query_params["limit"]
            
            return [self._transform_incident(i) for i in all_incidents]
        
        except Exception as e:
            logger.error(f"Failed to fetch incidents: {e}")
            return []
    
    async def _fetch_oncalls(
        self,
        start_time: datetime,
        end_time: datetime,
        params: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Fetch on-call schedules from PagerDuty."""
        try:
            query_params = {
                "since": start_time.isoformat(),
                "until": end_time.isoformat(),
                "limit": 100,
            }
            
            response = await self._make_request(
                "GET",
                "/oncalls",
                params=query_params
            )
            
            oncalls = response.get("oncalls", [])
            return [self._transform_oncall(o) for o in oncalls]
        
        except Exception as e:
            logger.error(f"Failed to fetch on-calls: {e}")
            return []
    
    async def _fetch_services(self, params: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Fetch services from PagerDuty."""
        try:
            query_params = {
                "limit": 100,
                "include[]": ["escalation_policies", "teams"],
            }
            
            response = await self._make_request(
                "GET",
                "/services",
                params=query_params
            )
            
            services = response.get("services", [])
            return [self._transform_service(s) for s in services]
        
        except Exception as e:
            logger.error(f"Failed to fetch services: {e}")
            return []
    
    def _transform_incident(self, incident: Dict[str, Any]) -> Dict[str, Any]:
        """Transform PagerDuty incident to Bronze format."""
        return {
            "source": "pagerduty",
            "source_type": "incident",
            "event_id": incident.get("id"),
            "timestamp": incident.get("created_at", datetime.utcnow().isoformat()),
            "severity": self._map_urgency_to_severity(incident.get("urgency", "low")),
            "title": incident.get("title", ""),
            "description": incident.get("description", ""),
            "status": incident.get("status", ""),
            "incident_number": incident.get("incident_number"),
            "urgency": incident.get("urgency", ""),
            "priority": incident.get("priority", {}),
            "service": incident.get("service", {}),
            "escalation_policy": incident.get("escalation_policy", {}),
            "teams": incident.get("teams", []),
            "assignments": incident.get("assignments", []),
            "acknowledgements": incident.get("acknowledgements", []),
            "last_status_change_at": incident.get("last_status_change_at", ""),
            "resolved_at": incident.get("resolved_at", ""),
            "html_url": incident.get("html_url", ""),
            "raw_data": incident,
            "ingested_at": datetime.utcnow().isoformat(),
        }
    
    def _transform_oncall(self, oncall: Dict[str, Any]) -> Dict[str, Any]:
        """Transform PagerDuty on-call to Bronze format."""
        return {
            "source": "pagerduty",
            "source_type": "oncall",
            "event_id": f"oncall_{oncall.get('user', {}).get('id', '')}_{oncall.get('schedule', {}).get('id', '')}",
            "timestamp": oncall.get("start", datetime.utcnow().isoformat()),
            "severity": "INFO",
            "title": f"On-call: {oncall.get('user', {}).get('summary', '')}",
            "description": f"Schedule: {oncall.get('schedule', {}).get('summary', '')}",
            "user": oncall.get("user", {}),
            "schedule": oncall.get("schedule", {}),
            "escalation_policy": oncall.get("escalation_policy", {}),
            "escalation_level": oncall.get("escalation_level"),
            "start": oncall.get("start", ""),
            "end": oncall.get("end", ""),
            "raw_data": oncall,
            "ingested_at": datetime.utcnow().isoformat(),
        }
    
    def _transform_service(self, service: Dict[str, Any]) -> Dict[str, Any]:
        """Transform PagerDuty service to Bronze format."""
        return {
            "source": "pagerduty",
            "source_type": "service",
            "event_id": service.get("id"),
            "timestamp": datetime.utcnow().isoformat(),
            "severity": "INFO",
            "title": service.get("name", ""),
            "description": service.get("description", ""),
            "status": service.get("status", ""),
            "service_name": service.get("name", ""),
            "escalation_policy": service.get("escalation_policy", {}),
            "teams": service.get("teams", []),
            "integrations": service.get("integrations", []),
            "incident_urgency_rule": service.get("incident_urgency_rule", {}),
            "alert_creation": service.get("alert_creation", ""),
            "html_url": service.get("html_url", ""),
            "raw_data": service,
            "ingested_at": datetime.utcnow().isoformat(),
        }
    
    @staticmethod
    def _map_urgency_to_severity(urgency: str) -> str:
        """Map PagerDuty urgency to severity level."""
        mapping = {
            "high": "HIGH",
            "low": "LOW",
        }
        return mapping.get(urgency.lower(), "MEDIUM")
