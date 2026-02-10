"""Tests for authentication and authorization."""
import pytest
from datetime import datetime, timedelta

from src.security.mfa_service import MFAService, MFAType, get_mfa_service
from src.security.service_auth import ServiceAuth, get_service_auth
from src.security.token_rotation import TokenRotation, get_token_rotation


class TestMFAService:
    """Test multi-factor authentication."""
    
    @pytest.fixture
    def mfa_service(self):
        """Create MFA service instance."""
        return MFAService()
    
    def test_generate_totp_secret(self, mfa_service):
        """Test TOTP secret generation."""
        secret = mfa_service.generate_totp_secret()
        
        assert secret is not None
        assert len(secret) == 32  # Base32 encoded
    
    def test_generate_totp_uri(self, mfa_service):
        """Test TOTP URI generation for QR code."""
        secret = "JBSWY3DPEHPK3PXP"
        uri = mfa_service.generate_totp_uri(secret, "user@example.com")
        
        assert uri.startswith("otpauth://totp/")
        assert "user@example.com" in uri
        assert secret in uri
    
    @pytest.mark.asyncio
    async def test_verify_totp_valid(self, mfa_service):
        """Test TOTP verification with valid code."""
        import pyotp
        
        secret = "JBSWY3DPEHPK3PXP"
        totp = pyotp.TOTP(secret)
        code = totp.now()
        
        is_valid = await mfa_service.verify_totp(secret, code)
        assert is_valid
    
    @pytest.mark.asyncio
    async def test_verify_totp_invalid(self, mfa_service):
        """Test TOTP verification with invalid code."""
        secret = "JBSWY3DPEHPK3PXP"
        
        is_valid = await mfa_service.verify_totp(secret, "000000")
        assert not is_valid
    
    @pytest.mark.asyncio
    async def test_totp_performance(self, mfa_service):
        """Test TOTP verification is under 100ms."""
        import time
        import pyotp
        
        secret = "JBSWY3DPEHPK3PXP"
        totp = pyotp.TOTP(secret)
        code = totp.now()
        
        start = time.perf_counter()
        await mfa_service.verify_totp(secret, code)
        duration = (time.perf_counter() - start) * 1000
        
        assert duration < 100  # Less than 100ms
    
    @pytest.mark.asyncio
    async def test_two_factor_login_flow_totp(self, mfa_service):
        """Test complete two-factor login flow."""
        import pyotp
        
        secret = "JBSWY3DPEHPK3PXP"
        totp = pyotp.TOTP(secret)
        code = totp.now()
        
        success, error = await mfa_service.two_factor_login_flow(
            username="testuser",
            password="password123",
            mfa_code=code,
            mfa_type=MFAType.TOTP,
            totp_secret=secret
        )
        
        assert success
        assert error is None


class TestServiceAuth:
    """Test service-to-service JWT authentication."""
    
    @pytest.fixture
    def service_auth(self):
        """Create service auth instance."""
        return ServiceAuth()
    
    def test_create_service_token(self, service_auth):
        """Test creating a service token."""
        token = service_auth.create_service_token(
            service_name="test-service",
            scopes=["incidents:read", "incidents:write"],
            expiry_days=30
        )
        
        assert token is not None
        assert isinstance(token, str)
    
    def test_verify_service_token(self, service_auth):
        """Test verifying a service token."""
        token = service_auth.create_service_token(
            service_name="test-service",
            scopes=["incidents:read"]
        )
        
        payload = service_auth.verify_service_token(token)
        
        assert payload is not None
        assert payload["sub"] == "test-service"
        assert payload["type"] == "service"
        assert "incidents:read" in payload["scopes"]
    
    def test_has_scope(self, service_auth):
        """Test checking token scopes."""
        token = service_auth.create_service_token(
            service_name="test-service",
            scopes=["incidents:read", "incidents:write"]
        )
        
        payload = service_auth.verify_service_token(token)
        
        assert service_auth.has_scope(payload, "incidents:read")
        assert service_auth.has_scope(payload, "incidents:write")
        assert not service_auth.has_scope(payload, "vulnerabilities:write")
    
    def test_admin_scope(self, service_auth):
        """Test admin:full scope grants all permissions."""
        token = service_auth.create_service_token(
            service_name="admin-service",
            scopes=["admin:full"]
        )
        
        payload = service_auth.verify_service_token(token)
        
        # Should have access to everything
        assert service_auth.has_scope(payload, "incidents:write")
        assert service_auth.has_scope(payload, "vulnerabilities:write")
        assert service_auth.has_scope(payload, "analytics:read")
    
    def test_require_scopes_success(self, service_auth):
        """Test require_scopes with valid token."""
        token = service_auth.create_service_token(
            service_name="test-service",
            scopes=["incidents:write"]
        )
        
        authorized, error = service_auth.require_scopes(
            token,
            ["incidents:write", "admin:full"]
        )
        
        assert authorized
        assert error is None
    
    def test_require_scopes_failure(self, service_auth):
        """Test require_scopes with insufficient scopes."""
        token = service_auth.create_service_token(
            service_name="test-service",
            scopes=["incidents:read"]
        )
        
        authorized, error = service_auth.require_scopes(
            token,
            ["incidents:write"]
        )
        
        assert not authorized
        assert error is not None
    
    def test_create_user_token(self, service_auth):
        """Test creating a user access token."""
        token = service_auth.create_user_token(
            user_id="user-123",
            email="user@example.com",
            roles=["user", "analyst"]
        )
        
        assert token is not None
    
    def test_verify_user_token(self, service_auth):
        """Test verifying a user token."""
        token = service_auth.create_user_token(
            user_id="user-123",
            email="user@example.com",
            roles=["user"]
        )
        
        payload = service_auth.verify_user_token(token)
        
        assert payload is not None
        assert payload["sub"] == "user-123"
        assert payload["email"] == "user@example.com"
        assert payload["type"] == "user"
    
    def test_extract_token_from_header(self, service_auth):
        """Test extracting token from Authorization header."""
        token = "abc123xyz"
        
        # Valid Bearer token
        extracted = service_auth.extract_token_from_header(f"Bearer {token}")
        assert extracted == token
        
        # Invalid format
        extracted = service_auth.extract_token_from_header("InvalidFormat")
        assert extracted is None


class TestTokenRotation:
    """Test refresh token rotation."""
    
    @pytest.fixture
    def token_rotation(self):
        """Create token rotation instance."""
        return TokenRotation()
    
    @pytest.mark.asyncio
    async def test_create_token_pair(self, token_rotation, test_db):
        """Test creating access + refresh token pair."""
        access_token, refresh_token = await token_rotation.create_token_pair(
            db=test_db,
            user_id="user-123",
            email="user@example.com",
            roles=["user"]
        )
        
        assert access_token is not None
        assert refresh_token is not None
        assert access_token != refresh_token
    
    @pytest.mark.asyncio
    async def test_rotate_refresh_token(self, token_rotation, test_db):
        """Test rotating refresh token."""
        # Create initial token pair
        _, old_refresh_token = await token_rotation.create_token_pair(
            db=test_db,
            user_id="user-123",
            email="user@example.com",
            roles=["user"]
        )
        
        # Rotate token
        result = await token_rotation.rotate_refresh_token(
            db=test_db,
            refresh_token=old_refresh_token,
            user_id="user-123",
            email="user@example.com",
            roles=["user"]
        )
        
        assert result is not None
        new_access_token, new_refresh_token = result
        assert new_refresh_token != old_refresh_token
    
    @pytest.mark.asyncio
    async def test_revoke_token(self, token_rotation, test_db):
        """Test revoking a refresh token."""
        _, refresh_token = await token_rotation.create_token_pair(
            db=test_db,
            user_id="user-123",
            email="user@example.com",
            roles=["user"]
        )
        
        # Revoke token
        revoked = await token_rotation.revoke_token(test_db, refresh_token)
        assert revoked
        
        # Try to use revoked token
        result = await token_rotation.rotate_refresh_token(
            db=test_db,
            refresh_token=refresh_token,
            user_id="user-123",
            email="user@example.com",
            roles=["user"]
        )
        
        assert result is None  # Should fail


class TestGlobalAuthInstances:
    """Test global singleton instances."""
    
    def test_get_mfa_service_singleton(self):
        """Test global MFA service is singleton."""
        s1 = get_mfa_service()
        s2 = get_mfa_service()
        assert s1 is s2
    
    def test_get_service_auth_singleton(self):
        """Test global service auth is singleton."""
        a1 = get_service_auth()
        a2 = get_service_auth()
        assert a1 is a2
    
    def test_get_token_rotation_singleton(self):
        """Test global token rotation is singleton."""
        t1 = get_token_rotation()
        t2 = get_token_rotation()
        assert t1 is t2
