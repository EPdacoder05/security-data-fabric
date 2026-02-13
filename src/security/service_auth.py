"""JWT-based service-to-service authentication."""

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

from jose import JWTError, jwt

from src.config.settings import settings


class ServiceAuthManager:
    """JWT-based service-to-service authentication manager.

    Provides token generation and validation for service principal
    authentication with automatic expiry handling.
    """

    def __init__(
        self,
        signing_key: Optional[str] = None,
        algorithm: Optional[str] = None,
        expiration_minutes: Optional[int] = None,
    ):
        """Initialize service authentication manager.

        Args:
            signing_key: JWT signing key. If not provided, uses key from settings.
            algorithm: JWT signing algorithm. Defaults to HS256.
            expiration_minutes: Token expiration time in minutes. Defaults to 15.
        """
        self._signing_key = signing_key or settings.jwt_signing_key
        if not self._signing_key:
            raise ValueError("JWT signing key must be provided")

        self._algorithm = algorithm or settings.jwt_algorithm
        self._expiration_minutes = expiration_minutes or settings.jwt_expiration_minutes

    def generate_token(
        self,
        service_id: str,
        service_name: str,
        scopes: Optional[list[str]] = None,
        additional_claims: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Generate JWT token for service principal.

        Args:
            service_id: Unique service identifier
            service_name: Human-readable service name
            scopes: List of permission scopes
            additional_claims: Additional JWT claims to include

        Returns:
            Encoded JWT token
        """
        now = datetime.now(timezone.utc)
        expiration = now + timedelta(minutes=self._expiration_minutes)

        claims = {
            "sub": service_id,
            "service_name": service_name,
            "iat": now,
            "exp": expiration,
            "type": "service",
        }

        if scopes:
            claims["scopes"] = scopes

        if additional_claims:
            claims.update(additional_claims)

        token = jwt.encode(claims, self._signing_key, algorithm=self._algorithm)

        return token  # type: ignore[return-value]

    def validate_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Validate JWT token and extract claims.

        Args:
            token: JWT token to validate

        Returns:
            Token claims if valid, None otherwise
        """
        try:
            claims = jwt.decode(token, self._signing_key, algorithms=[self._algorithm])

            if claims.get("type") != "service":
                return None

            return dict(claims)
        except JWTError:
            return None

    def is_token_expired(self, token: str) -> bool:
        """Check if token is expired.

        Args:
            token: JWT token to check

        Returns:
            True if expired or invalid, False otherwise
        """
        try:
            claims = jwt.decode(
                token,
                self._signing_key,
                algorithms=[self._algorithm],
                options={"verify_exp": False},
            )

            exp = claims.get("exp")
            if not exp:
                return True

            expiration_time = datetime.fromtimestamp(exp, tz=timezone.utc)
            return datetime.now(timezone.utc) >= expiration_time
        except JWTError:
            return True

    def get_service_id(self, token: str) -> Optional[str]:
        """Extract service ID from token.

        Args:
            token: JWT token

        Returns:
            Service ID if valid, None otherwise
        """
        claims = self.validate_token(token)
        if claims:
            return claims.get("sub")
        return None

    def get_scopes(self, token: str) -> list[str]:
        """Extract scopes from token.

        Args:
            token: JWT token

        Returns:
            List of scopes, empty list if invalid
        """
        claims = self.validate_token(token)
        if claims:
            return list(claims.get("scopes", []))
        return []

    def has_scope(self, token: str, required_scope: str) -> bool:
        """Check if token has required scope.

        Args:
            token: JWT token
            required_scope: Scope to check for

        Returns:
            True if token has scope, False otherwise
        """
        scopes = self.get_scopes(token)
        return required_scope in scopes

    def refresh_token(self, old_token: str, extend_expiration: bool = True) -> Optional[str]:
        """Refresh token with new expiration.

        Args:
            old_token: Existing JWT token
            extend_expiration: If True, extends expiration from current time

        Returns:
            New token if old token is valid, None otherwise
        """
        claims = self.validate_token(old_token)
        if not claims:
            return None

        service_id = claims.get("sub")
        service_name = claims.get("service_name")
        scopes = claims.get("scopes")

        additional_claims = {
            k: v
            for k, v in claims.items()
            if k not in ["sub", "service_name", "scopes", "iat", "exp", "type"]
        }

        return self.generate_token(
            service_id=str(service_id),
            service_name=str(service_name),
            scopes=scopes,
            additional_claims=additional_claims if additional_claims else None,
        )
