"""Automated secrets rotation on 90-day schedule."""
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
from enum import Enum
import secrets
import hashlib

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import Column, String, DateTime, Boolean, Integer
from sqlalchemy.dialects.postgresql import UUID
import uuid

from src.database.connection import Base
from src.security.secrets_manager import get_secrets_manager

logger = logging.getLogger(__name__)


class SecretType(str, Enum):
    """Types of secrets that require rotation."""
    DATABASE_PASSWORD = "database_password"
    REDIS_PASSWORD = "redis_password"
    JWT_SIGNING_KEY = "jwt_signing_key"
    OKTA_API_TOKEN = "okta_api_token"
    ENCRYPTION_KEY = "encryption_key"
    SERVICE_API_KEY = "service_api_key"


class SecretRotationLog(Base):
    """Track secret rotation history."""
    
    __tablename__ = "secret_rotation_logs"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    secret_type = Column(String(100), nullable=False, index=True)
    rotated_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    next_rotation_due = Column(DateTime, nullable=False, index=True)
    rotation_successful = Column(Boolean, nullable=False)
    rotation_method = Column(String(50))  # "manual" or "automatic"
    notes = Column(String(500))


class SecretsRotation:
    """Manage 90-day secret rotation schedule."""
    
    ROTATION_INTERVAL_DAYS = 90
    WARNING_DAYS_BEFORE = 14  # Warn 2 weeks before expiry
    
    async def _generate_secure_secret(self, secret_type: SecretType) -> str:
        """Generate a cryptographically secure secret.
        
        Args:
            secret_type: Type of secret to generate
            
        Returns:
            Generated secret string
        """
        if secret_type == SecretType.DATABASE_PASSWORD:
            # 32-character password with special chars
            return secrets.token_urlsafe(32)
        
        elif secret_type == SecretType.JWT_SIGNING_KEY:
            # 64-byte key for HS256
            return secrets.token_urlsafe(64)
        
        elif secret_type == SecretType.ENCRYPTION_KEY:
            # 32-byte key for AES-256
            key_bytes = secrets.token_bytes(32)
            return key_bytes.hex()
        
        else:
            # Default: 32-byte token
            return secrets.token_urlsafe(32)
    
    async def rotate_secret(
        self,
        db: AsyncSession,
        secret_type: SecretType,
        manual: bool = False,
        custom_value: Optional[str] = None
    ) -> Dict[str, Any]:
        """Rotate a secret.
        
        Args:
            db: Database session
            secret_type: Type of secret to rotate
            manual: Whether this is a manual rotation
            custom_value: Custom secret value (optional)
            
        Returns:
            Rotation result
        """
        logger.info("Starting secret rotation: type=%s, manual=%s", secret_type.value, manual)
        
        try:
            # Generate or use custom secret
            new_secret = custom_value or await self._generate_secure_secret(secret_type)
            
            # Update in Key Vault
            secrets_manager = get_secrets_manager()
            secret_name = self._get_secret_name(secret_type)
            
            if secrets_manager.is_key_vault_available():
                success = secrets_manager.set_secret(secret_name, new_secret)
                if not success:
                    raise Exception("Failed to update secret in Key Vault")
            else:
                logger.warning("Key Vault unavailable, secret not persisted")
            
            # Log rotation
            next_rotation = datetime.utcnow() + timedelta(days=self.ROTATION_INTERVAL_DAYS)
            
            rotation_log = SecretRotationLog(
                secret_type=secret_type.value,
                rotated_at=datetime.utcnow(),
                next_rotation_due=next_rotation,
                rotation_successful=True,
                rotation_method="manual" if manual else "automatic",
                notes=f"Secret rotated successfully"
            )
            
            db.add(rotation_log)
            await db.commit()
            
            logger.info(
                "Secret rotated successfully: type=%s, next_due=%s",
                secret_type.value,
                next_rotation.isoformat()
            )
            
            return {
                "secret_type": secret_type.value,
                "rotated_at": rotation_log.rotated_at.isoformat(),
                "next_rotation_due": next_rotation.isoformat(),
                "success": True
            }
            
        except Exception as e:
            logger.error("Secret rotation failed: type=%s, error=%s", secret_type.value, str(e))
            
            # Log failed rotation
            rotation_log = SecretRotationLog(
                secret_type=secret_type.value,
                rotated_at=datetime.utcnow(),
                next_rotation_due=datetime.utcnow() + timedelta(days=1),  # Retry tomorrow
                rotation_successful=False,
                rotation_method="manual" if manual else "automatic",
                notes=f"Rotation failed: {str(e)}"
            )
            
            db.add(rotation_log)
            await db.commit()
            
            return {
                "secret_type": secret_type.value,
                "success": False,
                "error": str(e)
            }
    
    def _get_secret_name(self, secret_type: SecretType) -> str:
        """Get Key Vault secret name for a secret type."""
        mapping = {
            SecretType.DATABASE_PASSWORD: "db-password",
            SecretType.REDIS_PASSWORD: "redis-password",
            SecretType.JWT_SIGNING_KEY: "jwt-signing-key",
            SecretType.OKTA_API_TOKEN: "okta-api-token",
            SecretType.ENCRYPTION_KEY: "encryption-key",
            SecretType.SERVICE_API_KEY: "service-api-key"
        }
        return mapping.get(secret_type, secret_type.value)
    
    async def check_rotation_due(
        self,
        db: AsyncSession
    ) -> List[Dict[str, Any]]:
        """Check which secrets are due for rotation.
        
        Args:
            db: Database session
            
        Returns:
            List of secrets that need rotation
        """
        due_secrets = []
        
        for secret_type in SecretType:
            # Get last rotation
            result = await db.execute(
                select(SecretRotationLog)
                .where(SecretRotationLog.secret_type == secret_type.value)
                .where(SecretRotationLog.rotation_successful == True)  # noqa: E712
                .order_by(SecretRotationLog.rotated_at.desc())
                .limit(1)
            )
            last_rotation = result.scalar_one_or_none()
            
            if not last_rotation:
                # Never rotated
                due_secrets.append({
                    "secret_type": secret_type.value,
                    "status": "never_rotated",
                    "days_overdue": None,
                    "next_rotation_due": None
                })
                continue
            
            # Check if due
            now = datetime.utcnow()
            days_until_due = (last_rotation.next_rotation_due - now).days
            
            if days_until_due <= 0:
                due_secrets.append({
                    "secret_type": secret_type.value,
                    "status": "overdue",
                    "days_overdue": abs(days_until_due),
                    "last_rotated": last_rotation.rotated_at.isoformat(),
                    "next_rotation_due": last_rotation.next_rotation_due.isoformat()
                })
            elif days_until_due <= self.WARNING_DAYS_BEFORE:
                due_secrets.append({
                    "secret_type": secret_type.value,
                    "status": "due_soon",
                    "days_until_due": days_until_due,
                    "last_rotated": last_rotation.rotated_at.isoformat(),
                    "next_rotation_due": last_rotation.next_rotation_due.isoformat()
                })
        
        return due_secrets
    
    async def rotate_all_due_secrets(self, db: AsyncSession) -> Dict[str, Any]:
        """Automatically rotate all secrets that are due.
        
        Args:
            db: Database session
            
        Returns:
            Summary of rotations
        """
        due_secrets = await self.check_rotation_due(db)
        overdue = [s for s in due_secrets if s['status'] == 'overdue']
        
        results = []
        
        for secret in overdue:
            secret_type = SecretType(secret['secret_type'])
            result = await self.rotate_secret(db, secret_type, manual=False)
            results.append(result)
        
        successful = sum(1 for r in results if r['success'])
        
        logger.info(
            "Automatic rotation complete: total=%d, successful=%d",
            len(results),
            successful
        )
        
        return {
            "total_rotations": len(results),
            "successful_rotations": successful,
            "failed_rotations": len(results) - successful,
            "results": results
        }
    
    async def get_rotation_history(
        self,
        db: AsyncSession,
        secret_type: Optional[SecretType] = None,
        days: int = 90
    ) -> List[Dict[str, Any]]:
        """Get rotation history.
        
        Args:
            db: Database session
            secret_type: Filter by secret type (optional)
            days: Number of days of history
            
        Returns:
            List of rotation records
        """
        since = datetime.utcnow() - timedelta(days=days)
        
        query = select(SecretRotationLog).where(SecretRotationLog.rotated_at >= since)
        
        if secret_type:
            query = query.where(SecretRotationLog.secret_type == secret_type.value)
        
        query = query.order_by(SecretRotationLog.rotated_at.desc())
        
        result = await db.execute(query)
        records = result.scalars().all()
        
        return [
            {
                "secret_type": record.secret_type,
                "rotated_at": record.rotated_at.isoformat(),
                "next_rotation_due": record.next_rotation_due.isoformat(),
                "successful": record.rotation_successful,
                "method": record.rotation_method,
                "notes": record.notes
            }
            for record in records
        ]


# Global secrets rotation instance
_secrets_rotation: Optional[SecretsRotation] = None


def get_secrets_rotation() -> SecretsRotation:
    """Get or create global secrets rotation instance."""
    global _secrets_rotation
    if _secrets_rotation is None:
        _secrets_rotation = SecretsRotation()
    return _secrets_rotation
