"""
ServiceNow Table API connector for Bronze layer ingestion.
Fetches incidents, changes, and configuration items.
"""
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
import logging
import base64

from src.bronze.base_connector import BaseConnector, ConnectorError
from src.config.settings import settings

logger = logging.getLogger(__name__)


class ServiceNowConnector(BaseConnector):
    """Connector for ServiceNow Table API."""
    
    def __init__(
        self,
        instance: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        timeout: float = 30.0,
        max_retries: int = 3,
    ):
        """
        Initialize ServiceNow connector.
        
        Args:
            instance: ServiceNow instance URL (e.g., https://dev12345.service-now.com)
            username: ServiceNow username (for basic auth)
            password: ServiceNow password (for basic auth)
            client_id: OAuth client ID
            client_secret: OAuth client secret
            timeout: Request timeout in seconds
            max_retries: Maximum number of retry attempts
        """
        instance_url = instance or settings.servicenow_instance or ""
        
        super().__init__(
            name="ServiceNow",
            base_url=instance_url,
            api_key=None,
            timeout=timeout,
            max_retries=max_retries,
        )
        
        self.username = username or settings.servicenow_username
        self.password = password or settings.servicenow_password
        self.client_id = client_id or settings.servicenow_client_id
        self.client_secret = client_secret or settings.servicenow_client_secret
        self._oauth_token: Optional[str] = None
        
        if not self.base_url:
            raise ValueError("ServiceNow instance URL is required")
        
        # Need either basic auth or OAuth credentials
        if not (self.username and self.password) and not (self.client_id and self.client_secret):
            raise ValueError("Either username/password or client_id/client_secret is required")
    
    def _get_headers(self) -> Dict[str, str]:
        """Get HTTP headers for ServiceNow API requests."""
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        
        if self._oauth_token:
            headers["Authorization"] = f"Bearer {self._oauth_token}"
        elif self.username and self.password:
            # Basic authentication
            credentials = f"{self.username}:{self.password}"
            encoded = base64.b64encode(credentials.encode()).decode()
            headers["Authorization"] = f"Basic {encoded}"
        
        return headers
    
    async def connect(self) -> bool:
        """Establish connection and authenticate."""
        # If using OAuth, get access token
        if self.client_id and self.client_secret:
            try:
                if self._client is None:
                    import httpx
                    self._client = httpx.AsyncClient(
                        base_url=self.base_url,
                        timeout=self.timeout,
                    )
                
                # OAuth token endpoint
                response = await self._client.post(
                    "/oauth_token.do",
                    data={
                        "grant_type": "client_credentials",
                        "client_id": self.client_id,
                        "client_secret": self.client_secret,
                    }
                )
                response.raise_for_status()
                
                result = response.json()
                self._oauth_token = result.get("access_token")
                
                if not self._oauth_token:
                    raise ConnectorError("Failed to obtain OAuth token")
                
                logger.info(f"{self.name} OAuth authentication successful")
            
            except Exception as e:
                logger.error(f"{self.name} OAuth authentication failed: {e}")
                raise ConnectorError(f"Failed to authenticate to {self.name}: {e}")
        
        return await super().connect()
    
    async def health_check(self) -> bool:
        """
        Check if the ServiceNow API is accessible.
        
        Returns:
            True if healthy, False otherwise
        """
        try:
            # Query a small result from sys_user table
            await self._make_request(
                "GET",
                "/api/now/table/sys_user",
                params={"sysparm_limit": 1}
            )
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
        Fetch events from ServiceNow.
        
        Args:
            start_time: Start of time range (default: last hour)
            end_time: End of time range (default: now)
            **kwargs: Additional parameters:
                - fetch_incidents: Fetch incidents (default: True)
                - fetch_changes: Fetch change requests (default: True)
                - fetch_cmdb: Fetch CMDB CI records (default: False)
                - incident_state: Filter incidents by state
                - change_state: Filter changes by state
        
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
        
        # Fetch change requests
        if kwargs.get("fetch_changes", True):
            changes = await self._fetch_changes(start_time, end_time, kwargs)
            all_events.extend(changes)
        
        # Fetch CMDB CIs (optional)
        if kwargs.get("fetch_cmdb", False):
            cmdb_items = await self._fetch_cmdb_items(kwargs)
            all_events.extend(cmdb_items)
        
        logger.info(f"Fetched {len(all_events)} events from {self.name}")
        return all_events
    
    async def _fetch_incidents(
        self,
        start_time: datetime,
        end_time: datetime,
        params: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Fetch incidents from ServiceNow."""
        try:
            # ServiceNow datetime format
            start_str = start_time.strftime("%Y-%m-%d %H:%M:%S")
            end_str = end_time.strftime("%Y-%m-%d %H:%M:%S")
            
            query = f"sys_created_on>={start_str}^sys_created_on<={end_str}"
            
            if "incident_state" in params:
                query += f"^state={params['incident_state']}"
            
            query_params = {
                "sysparm_query": query,
                "sysparm_limit": 1000,
                "sysparm_display_value": "true",
            }
            
            response = await self._make_request(
                "GET",
                "/api/now/table/incident",
                params=query_params
            )
            
            incidents = response.get("result", [])
            return [self._transform_incident(i) for i in incidents]
        
        except Exception as e:
            logger.error(f"Failed to fetch incidents: {e}")
            return []
    
    async def _fetch_changes(
        self,
        start_time: datetime,
        end_time: datetime,
        params: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Fetch change requests from ServiceNow."""
        try:
            start_str = start_time.strftime("%Y-%m-%d %H:%M:%S")
            end_str = end_time.strftime("%Y-%m-%d %H:%M:%S")
            
            query = f"sys_created_on>={start_str}^sys_created_on<={end_str}"
            
            if "change_state" in params:
                query += f"^state={params['change_state']}"
            
            query_params = {
                "sysparm_query": query,
                "sysparm_limit": 1000,
                "sysparm_display_value": "true",
            }
            
            response = await self._make_request(
                "GET",
                "/api/now/table/change_request",
                params=query_params
            )
            
            changes = response.get("result", [])
            return [self._transform_change(c) for c in changes]
        
        except Exception as e:
            logger.error(f"Failed to fetch changes: {e}")
            return []
    
    async def _fetch_cmdb_items(self, params: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Fetch CMDB configuration items from ServiceNow."""
        try:
            query_params = {
                "sysparm_limit": 500,
                "sysparm_display_value": "true",
            }
            
            response = await self._make_request(
                "GET",
                "/api/now/table/cmdb_ci",
                params=query_params
            )
            
            cis = response.get("result", [])
            return [self._transform_cmdb_item(ci) for ci in cis]
        
        except Exception as e:
            logger.error(f"Failed to fetch CMDB items: {e}")
            return []
    
    def _transform_incident(self, incident: Dict[str, Any]) -> Dict[str, Any]:
        """Transform ServiceNow incident to Bronze format."""
        return {
            "source": "servicenow",
            "source_type": "incident",
            "event_id": incident.get("sys_id"),
            "timestamp": incident.get("sys_created_on", datetime.utcnow().isoformat()),
            "severity": self._map_priority_to_severity(incident.get("priority", "5")),
            "title": incident.get("short_description", ""),
            "description": incident.get("description", ""),
            "number": incident.get("number", ""),
            "state": incident.get("state", ""),
            "priority": incident.get("priority", ""),
            "urgency": incident.get("urgency", ""),
            "impact": incident.get("impact", ""),
            "category": incident.get("category", ""),
            "subcategory": incident.get("subcategory", ""),
            "assigned_to": incident.get("assigned_to", ""),
            "assignment_group": incident.get("assignment_group", ""),
            "caller": incident.get("caller_id", ""),
            "opened_at": incident.get("opened_at", ""),
            "resolved_at": incident.get("resolved_at", ""),
            "closed_at": incident.get("closed_at", ""),
            "raw_data": incident,
            "ingested_at": datetime.utcnow().isoformat(),
        }
    
    def _transform_change(self, change: Dict[str, Any]) -> Dict[str, Any]:
        """Transform ServiceNow change request to Bronze format."""
        return {
            "source": "servicenow",
            "source_type": "change",
            "event_id": change.get("sys_id"),
            "timestamp": change.get("sys_created_on", datetime.utcnow().isoformat()),
            "severity": self._map_priority_to_severity(change.get("priority", "4")),
            "title": change.get("short_description", ""),
            "description": change.get("description", ""),
            "number": change.get("number", ""),
            "state": change.get("state", ""),
            "type": change.get("type", ""),
            "risk": change.get("risk", ""),
            "impact": change.get("impact", ""),
            "priority": change.get("priority", ""),
            "category": change.get("category", ""),
            "assigned_to": change.get("assigned_to", ""),
            "assignment_group": change.get("assignment_group", ""),
            "requested_by": change.get("requested_by", ""),
            "start_date": change.get("start_date", ""),
            "end_date": change.get("end_date", ""),
            "raw_data": change,
            "ingested_at": datetime.utcnow().isoformat(),
        }
    
    def _transform_cmdb_item(self, ci: Dict[str, Any]) -> Dict[str, Any]:
        """Transform ServiceNow CMDB CI to Bronze format."""
        return {
            "source": "servicenow",
            "source_type": "cmdb_ci",
            "event_id": ci.get("sys_id"),
            "timestamp": datetime.utcnow().isoformat(),
            "severity": "INFO",
            "title": f"CI: {ci.get('name', '')}",
            "description": ci.get("short_description", ""),
            "name": ci.get("name", ""),
            "ci_class": ci.get("sys_class_name", ""),
            "operational_status": ci.get("operational_status", ""),
            "environment": ci.get("environment", ""),
            "location": ci.get("location", ""),
            "managed_by": ci.get("managed_by", ""),
            "owned_by": ci.get("owned_by", ""),
            "raw_data": ci,
            "ingested_at": datetime.utcnow().isoformat(),
        }
    
    @staticmethod
    def _map_priority_to_severity(priority: str) -> str:
        """Map ServiceNow priority to severity level."""
        mapping = {
            "1": "CRITICAL",
            "2": "HIGH",
            "3": "MEDIUM",
            "4": "LOW",
            "5": "INFO",
        }
        return mapping.get(str(priority), "INFO")
