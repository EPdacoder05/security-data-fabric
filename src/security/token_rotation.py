"""Refresh token rotation for preventing token replay attacks."""

import hashlib
import logging
import secrets
import uuid
from datetime import datetime, timedelta
from typing import Optional, Tuple

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from src.database.models import RefreshToken
from src.security.service_auth import get_service_auth

logger = logging.getLogger(__name__)


class TokenRotation:
    """Refresh token rotation with single-use tokens."""

    REFRESH_TOKEN_EXPIRY_DAYS = 30

    def __init__(self) -> None:
        """Initialize token rotation service."""
        self.service_auth = get_service_auth()

    def _generate_refresh_token(self) -> str:
        """Generate a cryptographically secure refresh token."""
        return secrets.token_urlsafe(32)

    def _hash_token(self, token: str) -> str:
        """Hash token for secure storage."""
        return hashlib.sha256(token.encode()).hexdigest()

    async def create_token_pair(
        self, db: AsyncSession, user_id: str, email: str, roles: list[str]
    ) -> Tuple[str, str]:
        """Create access + refresh token pair.

        Args:
            db: Database session
            user_id: User's unique ID
            email: User's email
            roles: User's roles

        Returns:
            Tuple of (access_token, refresh_token)
        """
        # Create access token (short-lived)
        access_token = self.service_auth.create_user_token(
            user_id=user_id, email=email, roles=roles
        )

        # Create refresh token (long-lived)
        refresh_token = self._generate_refresh_token()
        token_hash = self._hash_token(refresh_token)

        # Store refresh token in database
        expires_at = datetime.utcnow() + timedelta(days=self.REFRESH_TOKEN_EXPIRY_DAYS)

        db_token = RefreshToken(
            id=uuid.uuid4(),
            user_id=uuid.UUID(user_id) if isinstance(user_id, str) else user_id,
            token_hash=token_hash,
            expires_at=expires_at,
            revoked=False,
        )

        db.add(db_token)
        await db.commit()

        logger.info(
            "Token pair created: user_id=%s, expires_at=%s", user_id, expires_at.isoformat()
        )

        return access_token, refresh_token

    async def rotate_refresh_token(
        self, db: AsyncSession, refresh_token: str, user_id: str, email: str, roles: list[str]
    ) -> Optional[Tuple[str, str]]:
        """Rotate refresh token (single-use).

        Args:
            db: Database session
            refresh_token: Current refresh token
            user_id: User's unique ID
            email: User's email
            roles: User's roles

        Returns:
            Tuple of (new_access_token, new_refresh_token) or None if invalid
        """
        token_hash = self._hash_token(refresh_token)

        # Find and validate refresh token
        result = await db.execute(
            select(RefreshToken)
            .where(RefreshToken.token_hash == token_hash)
            .where(RefreshToken.revoked.is_(False))
        )
        db_token = result.scalar_one_or_none()

        if not db_token:
            logger.warning("Invalid or revoked refresh token")
            return None

        # Check expiration
        if db_token.expires_at < datetime.utcnow():
            logger.warning("Expired refresh token: user_id=%s", user_id)

            # Mark as revoked
            await db.execute(
                update(RefreshToken).where(RefreshToken.id == db_token.id).values(revoked=True)
            )
            await db.commit()

            return None

        # Revoke old token (single-use)
        await db.execute(
            update(RefreshToken).where(RefreshToken.id == db_token.id).values(revoked=True)
        )

        # Create new token pair
        new_access_token, new_refresh_token = await self.create_token_pair(
            db=db, user_id=user_id, email=email, roles=roles
        )

        # Link old token to new one (for audit trail)
        new_token_hash = self._hash_token(new_refresh_token)
        result = await db.execute(
            select(RefreshToken).where(RefreshToken.token_hash == new_token_hash)
        )
        new_db_token = result.scalar_one()

        await db.execute(
            update(RefreshToken)
            .where(RefreshToken.id == db_token.id)
            .values(replaced_by=new_db_token.id)
        )

        await db.commit()

        logger.info(
            "Refresh token rotated: user_id=%s, old_token_id=%s, new_token_id=%s",
            user_id,
            db_token.id,
            new_db_token.id,
        )

        return new_access_token, new_refresh_token

    async def revoke_token(self, db: AsyncSession, refresh_token: str) -> bool:
        """Manually revoke a refresh token.

        Args:
            db: Database session
            refresh_token: Refresh token to revoke

        Returns:
            True if token was revoked
        """
        token_hash = self._hash_token(refresh_token)

        result = await db.execute(
            update(RefreshToken)
            .where(RefreshToken.token_hash == token_hash)
            .where(RefreshToken.revoked.is_(False))
            .values(revoked=True)
        )

        await db.commit()

        revoked = result.rowcount > 0

        if revoked:
            logger.info("Refresh token revoked: token_hash=%s", token_hash[:16])

        return revoked

    async def revoke_all_user_tokens(self, db: AsyncSession, user_id: str) -> int:
        """Revoke all refresh tokens for a user (e.g., on password change).

        Args:
            db: Database session
            user_id: User's unique ID

        Returns:
            Number of tokens revoked
        """
        user_uuid = uuid.UUID(user_id) if isinstance(user_id, str) else user_id

        result = await db.execute(
            update(RefreshToken)
            .where(RefreshToken.user_id == user_uuid)
            .where(RefreshToken.revoked.is_(False))
            .values(revoked=True)
        )

        await db.commit()

        count = result.rowcount

        logger.info("All user tokens revoked: user_id=%s, count=%d", user_id, count)

        return count

    async def cleanup_expired_tokens(self, db: AsyncSession) -> int:
        """Clean up expired refresh tokens (maintenance task).

        Args:
            db: Database session

        Returns:
            Number of tokens cleaned up
        """
        result = await db.execute(
            update(RefreshToken)
            .where(RefreshToken.expires_at < datetime.utcnow())
            .where(RefreshToken.revoked.is_(False))
            .values(revoked=True)
        )

        await db.commit()

        count = result.rowcount

        if count > 0:
            logger.info("Expired tokens cleaned up: count=%d", count)

        return count


# Global token rotation instance
_token_rotation: Optional[TokenRotation] = None


def get_token_rotation() -> TokenRotation:
    """Get or create global token rotation instance."""
    global _token_rotation
    if _token_rotation is None:
        _token_rotation = TokenRotation()
    return _token_rotation
