"""FastAPI dependency injection for authentication and database."""
from typing import Optional, AsyncGenerator
from datetime import datetime, timedelta, UTC
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError, jwt
from sqlalchemy.ext.asyncio import AsyncSession

from src.database import get_db
from src.config import settings
from src.observability import get_logger

logger = get_logger(__name__)

# Security scheme
security = HTTPBearer(auto_error=False)


class CurrentUser:
    """Represents the current authenticated user."""

    def __init__(self, user_id: str, username: str, roles: list[str]):
        self.user_id = user_id
        self.username = username
        self.roles = roles


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Create JWT access token.
    
    Args:
        data: Data to encode in token
        expires_delta: Token expiration delta
        
    Returns:
        Encoded JWT token
    """
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(UTC) + expires_delta
    else:
        expire = datetime.now(UTC) + timedelta(minutes=settings.jwt_expiration_minutes)
    
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, settings.jwt_secret_key, algorithm=settings.jwt_algorithm)
    return encoded_jwt


def decode_token(token: str) -> dict:
    """Decode and validate JWT token.
    
    Args:
        token: JWT token to decode
        
    Returns:
        Decoded token payload
        
    Raises:
        HTTPException: If token is invalid
    """
    try:
        payload = jwt.decode(
            token, settings.jwt_secret_key, algorithms=[settings.jwt_algorithm]
        )
        return payload
    except JWTError as e:
        logger.warning(f"JWT validation failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )


async def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
) -> Optional[CurrentUser]:
    """Get current authenticated user from JWT token.
    
    Args:
        credentials: HTTP bearer credentials
        
    Returns:
        Current user or None if no token provided
        
    Raises:
        HTTPException: If token is invalid
    """
    if not credentials:
        return None
    
    token = credentials.credentials
    payload = decode_token(token)
    
    user_id: str = payload.get("sub")
    username: str = payload.get("username")
    roles: list[str] = payload.get("roles", [])
    
    if user_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    return CurrentUser(user_id=user_id, username=username, roles=roles)


async def require_authenticated_user(
    current_user: Optional[CurrentUser] = Depends(get_current_user),
) -> CurrentUser:
    """Require authenticated user.
    
    Args:
        current_user: Current user from token
        
    Returns:
        Current authenticated user
        
    Raises:
        HTTPException: If user is not authenticated
    """
    if current_user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return current_user


def require_role(required_role: str):
    """Dependency factory to require specific role.
    
    Args:
        required_role: Role required for access
        
    Returns:
        Dependency function
    """
    async def role_checker(
        current_user: CurrentUser = Depends(require_authenticated_user),
    ) -> CurrentUser:
        if required_role not in current_user.roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Role '{required_role}' required",
            )
        return current_user
    
    return role_checker


async def get_database_session(
    db: AsyncSession = Depends(get_db),
) -> AsyncGenerator[AsyncSession, None]:
    """Get database session dependency.
    
    Args:
        db: Database session from get_db
        
    Yields:
        Database session
    """
    yield db


# Rate limiting dependency
class RateLimitDependency:
    """Dependency for rate limiting specific endpoints."""

    def __init__(self, max_requests: int = 10, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._requests: dict[str, list[datetime]] = {}

    async def __call__(self, current_user: Optional[CurrentUser] = Depends(get_current_user)):
        """Check rate limit for user."""
        # Use user_id or IP as key
        key = current_user.user_id if current_user else "anonymous"
        
        now = datetime.now(UTC)
        cutoff = now - timedelta(seconds=self.window_seconds)
        
        # Initialize or clean old requests
        if key not in self._requests:
            self._requests[key] = []
        self._requests[key] = [req_time for req_time in self._requests[key] if req_time > cutoff]
        
        # Check limit
        if len(self._requests[key]) >= self.max_requests:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Rate limit exceeded. Max {self.max_requests} requests per {self.window_seconds} seconds.",
            )
        
        self._requests[key].append(now)


# Pre-configured rate limiters
rate_limit_strict = RateLimitDependency(max_requests=5, window_seconds=60)
rate_limit_moderate = RateLimitDependency(max_requests=20, window_seconds=60)
