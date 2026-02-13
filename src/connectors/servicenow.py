"""ServiceNow connector for incident, change, and problem management."""

import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

from src.config.settings import settings
from src.connectors.base import BaseConnector

logger = logging.getLogger(__name__)


class ServiceNowConnector(BaseConnector):
    """ServiceNow integration connector.

    Provides methods to fetch incidents, changes, and problems from ServiceNow
    using the Table API. Supports filtering, pagination, and field selection.
    """

    def __init__(
        self,
        base_url: Optional[str] = None,
        api_token: Optional[str] = None,
        timeout: int = 30,
        max_retries: int = 3,
    ) -> None:
        """Initialize ServiceNow connector.

        Args:
            base_url: ServiceNow instance URL. If not provided, uses settings.
            api_token: API authentication token. If not provided, uses settings.
            timeout: Request timeout in seconds
            max_retries: Maximum number of retry attempts
        """
        base_url = base_url or settings.servicenow_url
        api_token = api_token or settings.servicenow_token

        if not base_url or not api_token:
            raise ValueError("ServiceNow URL and token must be provided")

        super().__init__(
            base_url=base_url,
            api_token=api_token,
            timeout=timeout,
            max_retries=max_retries,
        )

        self.api_version = "v2"
        self.table_api_path = f"/api/now/{self.api_version}/table"

    async def connect(self) -> bool:
        """Establish connection to ServiceNow.

        Returns:
            True if connection successful, False otherwise
        """
        try:
            if not self._client:
                self._client = await self._create_client()

            # Validate connection
            is_valid = await self.validate_connection()
            self._connected = is_valid

            if is_valid:
                logger.info("Successfully connected to ServiceNow")
            else:
                logger.error("Failed to connect to ServiceNow")

            return is_valid

        except Exception as e:
            logger.error(f"Error connecting to ServiceNow: {e}")
            self._connected = False
            return False

    async def disconnect(self) -> None:
        """Close connection to ServiceNow."""
        if self._client:
            await self._client.aclose()
            self._client = None
            self._connected = False
            logger.info("Disconnected from ServiceNow")

    async def validate_connection(self) -> bool:
        """Validate ServiceNow connection.

        Returns:
            True if connection is valid, False otherwise
        """
        try:
            # Test connection with a simple query
            await self._get(
                f"{self.table_api_path}/incident",
                params={"sysparm_limit": 1},
            )
            return True

        except Exception as e:
            logger.error(f"ServiceNow connection validation failed: {e}")
            return False

    async def fetch_data(
        self,
        endpoint: str,
        params: Optional[Dict[str, Any]] = None,
    ) -> List[Dict[str, Any]]:
        """Fetch data from ServiceNow.

        Args:
            endpoint: Table name (incident, change_request, problem, etc.)
            params: Optional query parameters

        Returns:
            List of records
        """
        full_endpoint = f"{self.table_api_path}/{endpoint}"
        response = await self._get(full_endpoint, params=params)
        return response.get("result", [])

    async def fetch_incidents(
        self,
        state: Optional[str] = None,
        priority: Optional[int] = None,
        assigned_to: Optional[str] = None,
        created_after: Optional[datetime] = None,
        created_before: Optional[datetime] = None,
        limit: int = 100,
        offset: int = 0,
        fields: Optional[List[str]] = None,
    ) -> List[Dict[str, Any]]:
        """Fetch incidents from ServiceNow.

        Args:
            state: Filter by state (e.g., 'new', 'in_progress', 'resolved')
            priority: Filter by priority (1-5, where 1 is highest)
            assigned_to: Filter by assigned user
            created_after: Filter by creation date (after)
            created_before: Filter by creation date (before)
            limit: Maximum number of records to return
            offset: Number of records to skip
            fields: Specific fields to return

        Returns:
            List of incident records
        """
        params: Dict[str, Any] = {
            "sysparm_limit": limit,
            "sysparm_offset": offset,
        }

        # Build query string
        query_parts = []

        if state:
            query_parts.append(f"state={state}")

        if priority is not None:
            query_parts.append(f"priority={priority}")

        if assigned_to:
            query_parts.append(f"assigned_to={assigned_to}")

        if created_after:
            created_after_str = created_after.strftime("%Y-%m-%d %H:%M:%S")
            query_parts.append(f"sys_created_on>={created_after_str}")

        if created_before:
            created_before_str = created_before.strftime("%Y-%m-%d %H:%M:%S")
            query_parts.append(f"sys_created_on<={created_before_str}")

        if query_parts:
            params["sysparm_query"] = "^".join(query_parts)

        if fields:
            params["sysparm_fields"] = ",".join(fields)

        logger.info(f"Fetching incidents with params: {params}")
        return await self.fetch_data("incident", params=params)

    async def fetch_changes(
        self,
        state: Optional[str] = None,
        risk: Optional[str] = None,
        type: Optional[str] = None,
        requested_by: Optional[str] = None,
        created_after: Optional[datetime] = None,
        created_before: Optional[datetime] = None,
        limit: int = 100,
        offset: int = 0,
        fields: Optional[List[str]] = None,
    ) -> List[Dict[str, Any]]:
        """Fetch change requests from ServiceNow.

        Args:
            state: Filter by state (e.g., 'new', 'assess', 'scheduled', 'implement')
            risk: Filter by risk level (e.g., 'high', 'medium', 'low')
            type: Filter by change type (e.g., 'standard', 'normal', 'emergency')
            requested_by: Filter by requester
            created_after: Filter by creation date (after)
            created_before: Filter by creation date (before)
            limit: Maximum number of records to return
            offset: Number of records to skip
            fields: Specific fields to return

        Returns:
            List of change request records
        """
        params: Dict[str, Any] = {
            "sysparm_limit": limit,
            "sysparm_offset": offset,
        }

        # Build query string
        query_parts = []

        if state:
            query_parts.append(f"state={state}")

        if risk:
            query_parts.append(f"risk={risk}")

        if type:
            query_parts.append(f"type={type}")

        if requested_by:
            query_parts.append(f"requested_by={requested_by}")

        if created_after:
            created_after_str = created_after.strftime("%Y-%m-%d %H:%M:%S")
            query_parts.append(f"sys_created_on>={created_after_str}")

        if created_before:
            created_before_str = created_before.strftime("%Y-%m-%d %H:%M:%S")
            query_parts.append(f"sys_created_on<={created_before_str}")

        if query_parts:
            params["sysparm_query"] = "^".join(query_parts)

        if fields:
            params["sysparm_fields"] = ",".join(fields)

        logger.info(f"Fetching changes with params: {params}")
        return await self.fetch_data("change_request", params=params)

    async def fetch_problems(
        self,
        state: Optional[str] = None,
        priority: Optional[int] = None,
        assigned_to: Optional[str] = None,
        created_after: Optional[datetime] = None,
        created_before: Optional[datetime] = None,
        limit: int = 100,
        offset: int = 0,
        fields: Optional[List[str]] = None,
    ) -> List[Dict[str, Any]]:
        """Fetch problems from ServiceNow.

        Args:
            state: Filter by state (e.g., 'new', 'assess', 'root_cause_analysis')
            priority: Filter by priority (1-5, where 1 is highest)
            assigned_to: Filter by assigned user
            created_after: Filter by creation date (after)
            created_before: Filter by creation date (before)
            limit: Maximum number of records to return
            offset: Number of records to skip
            fields: Specific fields to return

        Returns:
            List of problem records
        """
        params: Dict[str, Any] = {
            "sysparm_limit": limit,
            "sysparm_offset": offset,
        }

        # Build query string
        query_parts = []

        if state:
            query_parts.append(f"state={state}")

        if priority is not None:
            query_parts.append(f"priority={priority}")

        if assigned_to:
            query_parts.append(f"assigned_to={assigned_to}")

        if created_after:
            created_after_str = created_after.strftime("%Y-%m-%d %H:%M:%S")
            query_parts.append(f"sys_created_on>={created_after_str}")

        if created_before:
            created_before_str = created_before.strftime("%Y-%m-%d %H:%M:%S")
            query_parts.append(f"sys_created_on<={created_before_str}")

        if query_parts:
            params["sysparm_query"] = "^".join(query_parts)

        if fields:
            params["sysparm_fields"] = ",".join(fields)

        logger.info(f"Fetching problems with params: {params}")
        return await self.fetch_data("problem", params=params)

    async def get_incident_by_number(
        self, incident_number: str
    ) -> Optional[Dict[str, Any]]:
        """Get a specific incident by its number.

        Args:
            incident_number: Incident number (e.g., INC0001234)

        Returns:
            Incident record or None if not found
        """
        try:
            params = {
                "sysparm_query": f"number={incident_number}",
                "sysparm_limit": 1,
            }
            results = await self.fetch_data("incident", params=params)
            return results[0] if results else None

        except Exception as e:
            logger.error(f"Error fetching incident {incident_number}: {e}")
            return None

    async def get_change_by_number(
        self, change_number: str
    ) -> Optional[Dict[str, Any]]:
        """Get a specific change request by its number.

        Args:
            change_number: Change request number (e.g., CHG0001234)

        Returns:
            Change request record or None if not found
        """
        try:
            params = {
                "sysparm_query": f"number={change_number}",
                "sysparm_limit": 1,
            }
            results = await self.fetch_data("change_request", params=params)
            return results[0] if results else None

        except Exception as e:
            logger.error(f"Error fetching change {change_number}: {e}")
            return None

    async def get_problem_by_number(
        self, problem_number: str
    ) -> Optional[Dict[str, Any]]:
        """Get a specific problem by its number.

        Args:
            problem_number: Problem number (e.g., PRB0001234)

        Returns:
            Problem record or None if not found
        """
        try:
            params = {
                "sysparm_query": f"number={problem_number}",
                "sysparm_limit": 1,
            }
            results = await self.fetch_data("problem", params=params)
            return results[0] if results else None

        except Exception as e:
            logger.error(f"Error fetching problem {problem_number}: {e}")
            return None

    async def create_incident(
        self,
        short_description: str,
        description: str,
        caller_id: str,
        urgency: int = 3,
        impact: int = 3,
        category: Optional[str] = None,
        assignment_group: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Create a new incident in ServiceNow.

        Args:
            short_description: Brief description of the incident
            description: Detailed description
            caller_id: User ID of the caller
            urgency: Urgency level (1-3, where 1 is highest)
            impact: Impact level (1-3, where 1 is highest)
            category: Incident category
            assignment_group: Assignment group name

        Returns:
            Created incident record
        """
        incident_data = {
            "short_description": short_description,
            "description": description,
            "caller_id": caller_id,
            "urgency": urgency,
            "impact": impact,
        }

        if category:
            incident_data["category"] = category

        if assignment_group:
            incident_data["assignment_group"] = assignment_group

        logger.info(f"Creating incident: {short_description}")
        response = await self._post(
            f"{self.table_api_path}/incident",
            json_data=incident_data,
        )
        return response.get("result", {})
