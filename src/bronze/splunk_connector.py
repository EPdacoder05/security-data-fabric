"""
Splunk/OpenSearch REST API connector for Bronze layer ingestion.
Executes searches and fetches events from Splunk.
"""
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
import logging
import asyncio

from src.bronze.base_connector import BaseConnector, ConnectorError
from src.config.settings import settings

logger = logging.getLogger(__name__)


class SplunkConnector(BaseConnector):
    """Connector for Splunk REST API."""
    
    def __init__(
        self,
        base_url: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        bearer_token: Optional[str] = None,
        timeout: float = 60.0,
        max_retries: int = 3,
    ):
        """
        Initialize Splunk connector.
        
        Args:
            base_url: Splunk instance URL (e.g., https://splunk.example.com:8089)
            username: Splunk username (for basic auth)
            password: Splunk password (for basic auth)
            bearer_token: Bearer token (alternative to username/password)
            timeout: Request timeout in seconds
            max_retries: Maximum number of retry attempts
        """
        super().__init__(
            name="Splunk",
            base_url=base_url or settings.splunk_base_url or "",
            api_key=bearer_token or settings.splunk_bearer_token,
            timeout=timeout,
            max_retries=max_retries,
        )
        
        self.username = username or settings.splunk_username
        self.password = password or settings.splunk_password
        self._session_key: Optional[str] = None
        
        if not self.base_url:
            raise ValueError("Splunk base_url is required")
        
        # Need either bearer token or username/password
        if not self.api_key and not (self.username and self.password):
            raise ValueError("Either bearer_token or username/password is required")
    
    def _get_headers(self) -> Dict[str, str]:
        """Get HTTP headers for Splunk API requests."""
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
        }
        
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        elif self._session_key:
            headers["Authorization"] = f"Splunk {self._session_key}"
        
        return headers
    
    async def connect(self) -> bool:
        """Establish connection and authenticate."""
        # If using bearer token, skip session key generation
        if self.api_key:
            return await super().connect()
        
        # Generate session key from username/password
        try:
            if self._client is None:
                import httpx
                self._client = httpx.AsyncClient(
                    base_url=self.base_url,
                    timeout=self.timeout,
                    verify=False,  # Often needed for self-signed certs
                )
            
            response = await self._client.post(
                "/services/auth/login",
                data={
                    "username": self.username,
                    "password": self.password,
                    "output_mode": "json"
                }
            )
            response.raise_for_status()
            
            result = response.json()
            self._session_key = result.get("sessionKey")
            
            if not self._session_key:
                raise ConnectorError("Failed to obtain session key")
            
            logger.info(f"{self.name} authenticated successfully")
            return await self.health_check()
        
        except Exception as e:
            logger.error(f"{self.name} authentication failed: {e}")
            raise ConnectorError(f"Failed to authenticate to {self.name}: {e}")
    
    async def health_check(self) -> bool:
        """
        Check if the Splunk API is accessible.
        
        Returns:
            True if healthy, False otherwise
        """
        try:
            # Query server info
            await self._make_request("GET", "/services/server/info")
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
        Fetch events from Splunk.
        
        Args:
            start_time: Start of time range (default: last hour)
            end_time: End of time range (default: now)
            **kwargs: Additional parameters:
                - search_query: SPL search query (required)
                - index: Splunk index to search
                - max_results: Maximum number of results (default: 10000)
        
        Returns:
            List of raw event dictionaries in Bronze format
        """
        if start_time is None or end_time is None:
            start_time, end_time = self._get_default_time_range()
        
        search_query = kwargs.get("search_query")
        if not search_query:
            # Default search for notable events
            search_query = 'search index=* sourcetype="notable" OR tag=security'
        
        # Add time range to search
        earliest_time = start_time.strftime("%Y-%m-%dT%H:%M:%S")
        latest_time = end_time.strftime("%Y-%m-%dT%H:%M:%S")
        
        # Create search job
        search_id = await self._create_search_job(
            search_query,
            earliest_time,
            latest_time,
            kwargs
        )
        
        # Wait for job completion
        await self._wait_for_job(search_id)
        
        # Fetch results
        results = await self._fetch_search_results(search_id, kwargs)
        
        logger.info(f"Fetched {len(results)} events from {self.name}")
        return results
    
    async def _create_search_job(
        self,
        search_query: str,
        earliest_time: str,
        latest_time: str,
        params: Dict[str, Any]
    ) -> str:
        """Create a Splunk search job."""
        data = {
            "search": search_query,
            "earliest_time": earliest_time,
            "latest_time": latest_time,
            "output_mode": "json",
            "exec_mode": "normal",
        }
        
        if "index" in params:
            data["search"] = f'search index={params["index"]} {search_query}'
        
        response = await self._make_request(
            "POST",
            "/services/search/jobs",
            json=data
        )
        
        search_id = response.get("sid")
        if not search_id:
            raise ConnectorError("Failed to create search job")
        
        logger.info(f"Created search job: {search_id}")
        return search_id
    
    async def _wait_for_job(self, search_id: str, max_wait: int = 300):
        """Wait for search job to complete."""
        start_time = datetime.now()
        
        while (datetime.now() - start_time).seconds < max_wait:
            response = await self._make_request(
                "GET",
                f"/services/search/jobs/{search_id}",
                params={"output_mode": "json"}
            )
            
            entry = response.get("entry", [{}])[0]
            content = entry.get("content", {})
            is_done = content.get("isDone", False)
            
            if is_done:
                logger.info(f"Search job {search_id} completed")
                return
            
            await asyncio.sleep(2)
        
        raise ConnectorError(f"Search job {search_id} timeout")
    
    async def _fetch_search_results(
        self,
        search_id: str,
        params: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Fetch results from completed search job."""
        max_results = params.get("max_results", 10000)
        
        response = await self._make_request(
            "GET",
            f"/services/search/jobs/{search_id}/results",
            params={
                "output_mode": "json",
                "count": min(max_results, 50000),
            }
        )
        
        results = response.get("results", [])
        return [self._transform_event(e) for e in results]
    
    def _transform_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Transform Splunk event to Bronze format."""
        # Extract timestamp
        timestamp_str = event.get("_time", event.get("timestamp", ""))
        try:
            if timestamp_str:
                timestamp = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
            else:
                timestamp = datetime.utcnow()
        except:
            timestamp = datetime.utcnow()
        
        # Extract severity
        severity = event.get("severity", event.get("urgency", "INFO")).upper()
        
        return {
            "source": "splunk",
            "source_type": event.get("sourcetype", "unknown"),
            "event_id": event.get("_cd", event.get("event_id", "")),
            "timestamp": timestamp.isoformat(),
            "severity": severity,
            "title": event.get("title", event.get("name", "Splunk Event")),
            "description": event.get("description", event.get("message", "")),
            "index": event.get("index", ""),
            "source_name": event.get("source", ""),
            "host": event.get("host", ""),
            "raw": event.get("_raw", ""),
            "fields": {k: v for k, v in event.items() if not k.startswith("_")},
            "raw_data": event,
            "ingested_at": datetime.utcnow().isoformat(),
        }
