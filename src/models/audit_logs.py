"""Audit log operations for compliance and security tracking."""

from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import UUID

from sqlalchemy import and_, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.database.connection import get_db_context
from src.database.models import AuditLog


class AuditEventType(str, Enum):
    """Types of auditable events."""

    # Authentication events
    AUTH_LOGIN = "auth.login"
    AUTH_LOGOUT = "auth.logout"
    AUTH_FAILED_LOGIN = "auth.failed_login"
    AUTH_MFA_VERIFY = "auth.mfa_verify"
    AUTH_PASSWORD_CHANGE = "auth.password_change"
    AUTH_TOKEN_REFRESH = "auth.token_refresh"

    # Data access events
    DATA_READ = "data.read"
    DATA_CREATE = "data.create"
    DATA_UPDATE = "data.update"
    DATA_DELETE = "data.delete"
    DATA_EXPORT = "data.export"
    DATA_QUERY = "data.query"

    # Configuration events
    CONFIG_CREATE = "config.create"
    CONFIG_UPDATE = "config.update"
    CONFIG_DELETE = "config.delete"

    # User management events
    USER_CREATE = "user.create"
    USER_UPDATE = "user.update"
    USER_DELETE = "user.delete"
    USER_ROLE_CHANGE = "user.role_change"
    USER_PERMISSION_CHANGE = "user.permission_change"

    # System events
    SYSTEM_START = "system.start"
    SYSTEM_STOP = "system.stop"
    SYSTEM_ERROR = "system.error"
    SYSTEM_BACKUP = "system.backup"
    SYSTEM_RESTORE = "system.restore"

    # Security events
    SECURITY_ALERT = "security.alert"
    SECURITY_BREACH = "security.breach"
    SECURITY_SCAN = "security.scan"
    SECURITY_VULNERABILITY = "security.vulnerability"

    # Compliance events
    COMPLIANCE_CHECK = "compliance.check"
    COMPLIANCE_REPORT = "compliance.report"
    COMPLIANCE_EVIDENCE = "compliance.evidence"


class AuditLogManager:
    """Manager for audit log operations.

    This class provides methods to create, query, and filter audit logs
    for compliance and security tracking purposes. All operations are
    async and support the 7-year retention requirement for SOC2 compliance.
    """

    def __init__(self, session: Optional[AsyncSession] = None) -> None:
        """Initialize audit log manager.

        Args:
            session: Optional AsyncSession. If not provided, will create sessions as needed.
        """
        self._session = session

    async def create_log(
        self,
        action: str,
        resource_type: str,
        user_id: Optional[UUID] = None,
        resource_id: Optional[str] = None,
        changes: Optional[Dict[str, Any]] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        request_id: Optional[UUID] = None,
        additional_data: Optional[Dict[str, Any]] = None,
    ) -> AuditLog:
        """Create a new audit log entry.

        Args:
            action: Action performed (use AuditEventType enum values)
            resource_type: Type of resource affected
            user_id: ID of user performing action
            resource_id: ID of affected resource
            changes: Dictionary of changes made
            ip_address: IP address of requester
            user_agent: User agent string
            request_id: Request correlation ID
            additional_data: Any additional metadata to store

        Returns:
            Created AuditLog instance
        """
        # Merge additional_data into changes if provided
        if additional_data:
            changes = changes or {}
            changes.update(additional_data)

        log = AuditLog(
            timestamp=datetime.now(timezone.utc),
            user_id=user_id,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            changes=changes,
            ip_address=ip_address,
            user_agent=user_agent,
            request_id=request_id,
        )

        if self._session:
            self._session.add(log)
            await self._session.flush()
        else:
            async with get_db_context() as session:
                session.add(log)
                await session.flush()

        return log

    async def get_log(
        self, log_id: UUID, session: Optional[AsyncSession] = None
    ) -> Optional[AuditLog]:
        """Get a specific audit log by ID.

        Args:
            log_id: UUID of the audit log
            session: Optional AsyncSession

        Returns:
            AuditLog instance or None if not found
        """
        db_session = session or self._session
        if db_session:
            result = await db_session.execute(select(AuditLog).where(AuditLog.id == log_id))
            return result.scalar_one_or_none()  # type: ignore[return-value]
        else:
            async with get_db_context() as db_session:
                result = await db_session.execute(select(AuditLog).where(AuditLog.id == log_id))
                return result.scalar_one_or_none()  # type: ignore[return-value]

    async def get_logs_by_user(
        self,
        user_id: UUID,
        limit: int = 100,
        offset: int = 0,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        session: Optional[AsyncSession] = None,
    ) -> List[AuditLog]:
        """Get audit logs for a specific user.

        Args:
            user_id: UUID of the user
            limit: Maximum number of logs to return
            offset: Number of logs to skip
            start_date: Optional start date filter
            end_date: Optional end date filter
            session: Optional AsyncSession

        Returns:
            List of AuditLog instances
        """
        db_session = session or self._session

        query = select(AuditLog).where(AuditLog.user_id == user_id)

        if start_date:
            query = query.where(AuditLog.timestamp >= start_date)
        if end_date:
            query = query.where(AuditLog.timestamp <= end_date)

        query = query.order_by(AuditLog.timestamp.desc()).limit(limit).offset(offset)

        if db_session:
            result = await db_session.execute(query)
            return list(result.scalars().all())
        else:
            async with get_db_context() as db_session:
                result = await db_session.execute(query)
                return list(result.scalars().all())

    async def get_logs_by_action(
        self,
        action: str,
        limit: int = 100,
        offset: int = 0,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        session: Optional[AsyncSession] = None,
    ) -> List[AuditLog]:
        """Get audit logs for a specific action type.

        Args:
            action: Action type (use AuditEventType enum values)
            limit: Maximum number of logs to return
            offset: Number of logs to skip
            start_date: Optional start date filter
            end_date: Optional end date filter
            session: Optional AsyncSession

        Returns:
            List of AuditLog instances
        """
        db_session = session or self._session

        query = select(AuditLog).where(AuditLog.action == action)

        if start_date:
            query = query.where(AuditLog.timestamp >= start_date)
        if end_date:
            query = query.where(AuditLog.timestamp <= end_date)

        query = query.order_by(AuditLog.timestamp.desc()).limit(limit).offset(offset)

        if db_session:
            result = await db_session.execute(query)
            return list(result.scalars().all())
        else:
            async with get_db_context() as db_session:
                result = await db_session.execute(query)
                return list(result.scalars().all())

    async def get_logs_by_resource(
        self,
        resource_type: str,
        resource_id: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        session: Optional[AsyncSession] = None,
    ) -> List[AuditLog]:
        """Get audit logs for a specific resource.

        Args:
            resource_type: Type of resource
            resource_id: Optional specific resource ID
            limit: Maximum number of logs to return
            offset: Number of logs to skip
            start_date: Optional start date filter
            end_date: Optional end date filter
            session: Optional AsyncSession

        Returns:
            List of AuditLog instances
        """
        db_session = session or self._session

        conditions = [AuditLog.resource_type == resource_type]
        if resource_id:
            conditions.append(AuditLog.resource_id == resource_id)

        query = select(AuditLog).where(and_(*conditions))

        if start_date:
            query = query.where(AuditLog.timestamp >= start_date)
        if end_date:
            query = query.where(AuditLog.timestamp <= end_date)

        query = query.order_by(AuditLog.timestamp.desc()).limit(limit).offset(offset)

        if db_session:
            result = await db_session.execute(query)
            return list(result.scalars().all())
        else:
            async with get_db_context() as db_session:
                result = await db_session.execute(query)
                return list(result.scalars().all())

    async def get_logs_by_request(
        self,
        request_id: UUID,
        session: Optional[AsyncSession] = None,
    ) -> List[AuditLog]:
        """Get all audit logs for a specific request.

        Args:
            request_id: Request correlation ID
            session: Optional AsyncSession

        Returns:
            List of AuditLog instances for the request
        """
        db_session = session or self._session

        query = (
            select(AuditLog)
            .where(AuditLog.request_id == request_id)
            .order_by(AuditLog.timestamp.asc())
        )

        if db_session:
            result = await db_session.execute(query)
            return list(result.scalars().all())
        else:
            async with get_db_context() as db_session:
                result = await db_session.execute(query)
                return list(result.scalars().all())

    async def search_logs(
        self,
        user_id: Optional[UUID] = None,
        action: Optional[str] = None,
        resource_type: Optional[str] = None,
        resource_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        limit: int = 100,
        offset: int = 0,
        session: Optional[AsyncSession] = None,
    ) -> List[AuditLog]:
        """Search audit logs with multiple filters.

        Args:
            user_id: Filter by user ID
            action: Filter by action type
            resource_type: Filter by resource type
            resource_id: Filter by resource ID
            ip_address: Filter by IP address
            start_date: Filter by start date
            end_date: Filter by end date
            limit: Maximum number of logs to return
            offset: Number of logs to skip
            session: Optional AsyncSession

        Returns:
            List of matching AuditLog instances
        """
        db_session = session or self._session

        conditions = []
        if user_id:
            conditions.append(AuditLog.user_id == user_id)
        if action:
            conditions.append(AuditLog.action == action)
        if resource_type:
            conditions.append(AuditLog.resource_type == resource_type)
        if resource_id:
            conditions.append(AuditLog.resource_id == resource_id)
        if ip_address:
            conditions.append(AuditLog.ip_address == ip_address)
        if start_date:
            conditions.append(AuditLog.timestamp >= start_date)
        if end_date:
            conditions.append(AuditLog.timestamp <= end_date)

        query = select(AuditLog)
        if conditions:
            query = query.where(and_(*conditions))

        query = query.order_by(AuditLog.timestamp.desc()).limit(limit).offset(offset)

        if db_session:
            result = await db_session.execute(query)
            return list(result.scalars().all())
        else:
            async with get_db_context() as db_session:
                result = await db_session.execute(query)
                return list(result.scalars().all())

    async def get_failed_login_attempts(
        self,
        user_id: Optional[UUID] = None,
        ip_address: Optional[str] = None,
        hours: int = 24,
        session: Optional[AsyncSession] = None,
    ) -> List[AuditLog]:
        """Get failed login attempts within a time window.

        Args:
            user_id: Optional filter by user ID
            ip_address: Optional filter by IP address
            hours: Time window in hours (default: 24)
            session: Optional AsyncSession

        Returns:
            List of failed login AuditLog instances
        """
        start_date = datetime.now(timezone.utc) - timedelta(hours=hours)

        return await self.search_logs(
            user_id=user_id,
            action=AuditEventType.AUTH_FAILED_LOGIN.value,
            ip_address=ip_address,
            start_date=start_date,
            session=session,
        )

    async def get_user_activity_summary(
        self,
        user_id: UUID,
        start_date: datetime,
        end_date: datetime,
        session: Optional[AsyncSession] = None,
    ) -> Dict[str, Any]:
        """Get activity summary for a user.

        Args:
            user_id: UUID of the user
            start_date: Start date for summary
            end_date: End date for summary
            session: Optional AsyncSession

        Returns:
            Dictionary containing activity summary
        """
        logs = await self.get_logs_by_user(
            user_id=user_id,
            start_date=start_date,
            end_date=end_date,
            limit=10000,  # High limit for summary
            session=session,
        )

        # Count actions by type
        action_counts: Dict[str, int] = {}
        resource_counts: Dict[str, int] = {}
        ip_addresses = set()

        for log in logs:
            action_counts[str(log.action)] = action_counts.get(str(log.action), 0) + 1
            resource_counts[str(log.resource_type)] = (
                resource_counts.get(str(log.resource_type), 0) + 1
            )
            if log.ip_address:
                ip_addresses.add(log.ip_address)

        return {
            "user_id": str(user_id),
            "start_date": start_date.isoformat(),
            "end_date": end_date.isoformat(),
            "total_actions": len(logs),
            "action_breakdown": action_counts,
            "resource_breakdown": resource_counts,
            "unique_ip_addresses": len(ip_addresses),
            "ip_addresses": list(ip_addresses),
        }

    async def count_logs(
        self,
        user_id: Optional[UUID] = None,
        action: Optional[str] = None,
        resource_type: Optional[str] = None,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        session: Optional[AsyncSession] = None,
    ) -> int:
        """Count audit logs matching filters.

        Args:
            user_id: Filter by user ID
            action: Filter by action type
            resource_type: Filter by resource type
            start_date: Filter by start date
            end_date: Filter by end date
            session: Optional AsyncSession

        Returns:
            Count of matching logs
        """
        logs = await self.search_logs(
            user_id=user_id,
            action=action,
            resource_type=resource_type,
            start_date=start_date,
            end_date=end_date,
            limit=100000,  # High limit for counting
            session=session,
        )
        return len(logs)
