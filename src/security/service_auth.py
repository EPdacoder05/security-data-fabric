"""Service-to-service JWT authentication with scope-based authorization."""
import logging
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any
import uuid

from jose import jwt, JWTError

from src.config import settings

logger = logging.getLogger(__name__)


class ServiceAuth:
    """Service-to-service authentication using JWT tokens."""
    
    # Service scopes for authorization
    VALID_SCOPES = {
        "incidents:read",
        "incidents:write",
        "vulnerabilities:read",
        "vulnerabilities:write",
        "alerts:read",
        "alerts:write",
        "analytics:read",
        "analytics:write",
        "admin:full",
    }
    
    def __init__(self) -> None:
        """Initialize service auth."""
        self.algorithm = settings.jwt_algorithm
        self.signing_key = settings.jwt_signing_key or "development-jwt-key"
    
    def create_service_token(
        self,
        service_name: str,
        scopes: List[str],
        expiry_days: int = 30
    ) -> str:
        """Create a service token with scopes.
        
        Args:
            service_name: Name of the service (e.g., "incident-processor")
            scopes: List of allowed scopes
            expiry_days: Token expiration in days (default: 30)
            
        Returns:
            JWT token string
            
        Example:
            token = auth.create_service_token(
                "incident-processor",
                ["incidents:write", "alerts:write"]
            )
        """
        # Validate scopes
        invalid_scopes = set(scopes) - self.VALID_SCOPES
        if invalid_scopes:
            raise ValueError(f"Invalid scopes: {invalid_scopes}")
        
        # Create JWT payload
        now = datetime.utcnow()
        expires_at = now + timedelta(days=expiry_days)
        
        payload = {
            "sub": service_name,
            "type": "service",
            "scopes": scopes,
            "iat": now,
            "exp": expires_at,
            "jti": str(uuid.uuid4()),  # Unique token ID
        }
        
        # Sign token
        token = jwt.encode(payload, self.signing_key, algorithm=self.algorithm)
        
        logger.info(
            "Service token created: service=%s, scopes=%s, expires=%s",
            service_name,
            ",".join(scopes),
            expires_at.isoformat()
        )
        
        return token
    
    def verify_service_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Verify and decode service token.
        
        Args:
            token: JWT token string
            
        Returns:
            Decoded token payload or None if invalid
        """
        try:
            payload = jwt.decode(
                token,
                self.signing_key,
                algorithms=[self.algorithm]
            )
            
            # Verify token type
            if payload.get("type") != "service":
                logger.warning("Token is not a service token")
                return None
            
            logger.debug("Service token verified: service=%s", payload.get("sub"))
            return payload
            
        except JWTError as e:
            logger.warning("Invalid service token: %s", str(e))
            return None
    
    def has_scope(self, token_payload: Dict[str, Any], required_scope: str) -> bool:
        """Check if token has required scope.
        
        Args:
            token_payload: Decoded JWT payload
            required_scope: Required scope (e.g., "incidents:write")
            
        Returns:
            True if token has scope or admin:full
        """
        scopes = token_payload.get("scopes", [])
        
        # admin:full grants all permissions
        if "admin:full" in scopes:
            return True
        
        return required_scope in scopes
    
    def require_scopes(
        self,
        token: str,
        required_scopes: List[str]
    ) -> tuple[bool, Optional[str]]:
        """Verify token and check for required scopes.
        
        Args:
            token: JWT token string
            required_scopes: List of required scopes (user needs at least one)
            
        Returns:
            Tuple of (authorized, error_message)
            
        Example:
            authorized, error = auth.require_scopes(
                token,
                ["incidents:write", "admin:full"]
            )
        """
        # Verify token
        payload = self.verify_service_token(token)
        if not payload:
            return False, "Invalid or expired token"
        
        # Check scopes
        token_scopes = payload.get("scopes", [])
        
        # admin:full grants all permissions
        if "admin:full" in token_scopes:
            return True, None
        
        # Check if any required scope is present
        has_required = any(scope in token_scopes for scope in required_scopes)
        
        if not has_required:
            return False, f"Missing required scope (need one of: {', '.join(required_scopes)})"
        
        return True, None
    
    def create_user_token(
        self,
        user_id: str,
        email: str,
        roles: List[str],
        expiry_minutes: Optional[int] = None
    ) -> str:
        """Create a user access token.
        
        Args:
            user_id: User's unique ID
            email: User's email
            roles: User's roles
            expiry_minutes: Token expiration (default: from settings)
            
        Returns:
            JWT token string
        """
        expiry = expiry_minutes or settings.jwt_expiration_minutes
        
        now = datetime.utcnow()
        expires_at = now + timedelta(minutes=expiry)
        
        payload = {
            "sub": user_id,
            "email": email,
            "roles": roles,
            "type": "user",
            "iat": now,
            "exp": expires_at,
            "jti": str(uuid.uuid4()),
        }
        
        token = jwt.encode(payload, self.signing_key, algorithm=self.algorithm)
        
        logger.info(
            "User token created: user_id=%s, roles=%s, expires_in=%dm",
            user_id,
            ",".join(roles),
            expiry
        )
        
        return token
    
    def verify_user_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Verify and decode user token.
        
        Args:
            token: JWT token string
            
        Returns:
            Decoded token payload or None if invalid
        """
        try:
            payload = jwt.decode(
                token,
                self.signing_key,
                algorithms=[self.algorithm]
            )
            
            # Verify token type
            if payload.get("type") != "user":
                logger.warning("Token is not a user token")
                return None
            
            logger.debug("User token verified: user_id=%s", payload.get("sub"))
            return payload
            
        except JWTError as e:
            logger.warning("Invalid user token: %s", str(e))
            return None
    
    def extract_token_from_header(self, authorization: str) -> Optional[str]:
        """Extract JWT token from Authorization header.
        
        Args:
            authorization: Authorization header value
            
        Returns:
            Token string or None
            
        Example:
            token = auth.extract_token_from_header("Bearer eyJ...")
        """
        if not authorization:
            return None
        
        parts = authorization.split()
        if len(parts) != 2 or parts[0].lower() != "bearer":
            return None
        
        return parts[1]


# Global service auth instance
_service_auth: Optional[ServiceAuth] = None


def get_service_auth() -> ServiceAuth:
    """Get or create global service auth instance."""
    global _service_auth
    if _service_auth is None:
        _service_auth = ServiceAuth()
    return _service_auth
