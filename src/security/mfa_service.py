"""Multi-Factor Authentication service with Okta integration."""
import logging
import time
from enum import Enum
from typing import Optional

import httpx
import pyotp

from src.config import settings

logger = logging.getLogger(__name__)


class MFAType(str, Enum):
    """MFA verification methods."""
    TOTP = "totp"  # Google Authenticator, Authy
    SMS = "sms"
    EMAIL = "email"
    PUSH = "push"  # Okta Verify push notification
    WEBAUTHN = "webauthn"  # Hardware keys, biometrics


class MFAService:
    """Multi-factor authentication service."""

    def __init__(self) -> None:
        """Initialize MFA service."""
        self.okta_domain = settings.okta_domain
        self.okta_client_id = settings.okta_client_id
        self.okta_client_secret = settings.okta_client_secret
        self._http_client: Optional[httpx.AsyncClient] = None

    async def _get_http_client(self) -> httpx.AsyncClient:
        """Get or create HTTP client."""
        if self._http_client is None:
            self._http_client = httpx.AsyncClient(
                timeout=10.0,
                headers={
                    "Accept": "application/json",
                    "Content-Type": "application/json",
                }
            )
        return self._http_client

    def generate_totp_secret(self) -> str:
        """Generate a new TOTP secret for user enrollment.
        
        Returns:
            Base32-encoded secret string
        """
        return pyotp.random_base32()

    def generate_totp_uri(
        self,
        secret: str,
        user_email: str,
        issuer: str = "Security Data Fabric"
    ) -> str:
        """Generate TOTP provisioning URI for QR code.
        
        Args:
            secret: TOTP secret
            user_email: User's email address
            issuer: Application name
            
        Returns:
            otpauth:// URI for QR code generation
        """
        totp = pyotp.TOTP(secret)
        return totp.provisioning_uri(name=user_email, issuer_name=issuer)

    async def verify_totp(
        self,
        secret: str,
        code: str,
        window: int = 1
    ) -> bool:
        """Verify TOTP code with time window tolerance.
        
        Args:
            secret: User's TOTP secret
            code: 6-digit code from authenticator app
            window: Number of time windows to check (default: ±30 seconds)
            
        Returns:
            True if code is valid
        """
        start_time = time.perf_counter()

        try:
            totp = pyotp.TOTP(secret)
            is_valid = totp.verify(code, valid_window=window)

            duration = (time.perf_counter() - start_time) * 1000

            if is_valid:
                logger.info("TOTP verification SUCCESS (%.2fms)", duration)
            else:
                logger.warning("TOTP verification FAILED (%.2fms)", duration)

            return is_valid

        except Exception as e:
            logger.error("TOTP verification error: %s", str(e))
            return False

    async def send_sms_code(self, phone_number: str, user_id: str) -> Optional[str]:
        """Send SMS verification code via Okta.
        
        Args:
            phone_number: User's phone number (E.164 format)
            user_id: Okta user ID
            
        Returns:
            Transaction ID for verification or None on error
        """
        if not self.okta_domain or not self.okta_client_secret:
            logger.warning("Okta not configured for SMS MFA")
            return None

        try:
            client = await self._get_http_client()
            url = f"https://{self.okta_domain}/api/v1/users/{user_id}/factors"

            response = await client.post(
                url,
                json={
                    "factorType": "sms",
                    "provider": "OKTA",
                    "profile": {
                        "phoneNumber": phone_number
                    }
                },
                headers={
                    "Authorization": f"SSWS {self.okta_client_secret}"
                }
            )

            if response.status_code == 200:
                data = response.json()
                logger.info("SMS code sent to %s", phone_number[-4:])
                return data.get("id")
            else:
                logger.error("SMS send failed: %s", response.text)
                return None

        except Exception as e:
            logger.error("SMS send error: %s", str(e))
            return None

    async def verify_sms_code(
        self,
        factor_id: str,
        code: str,
        user_id: str
    ) -> bool:
        """Verify SMS code via Okta.
        
        Args:
            factor_id: Okta factor ID from send_sms_code
            code: 6-digit SMS code
            user_id: Okta user ID
            
        Returns:
            True if code is valid
        """
        start_time = time.perf_counter()

        if not self.okta_domain or not self.okta_client_secret:
            logger.warning("Okta not configured for SMS MFA")
            return False

        try:
            client = await self._get_http_client()
            url = f"https://{self.okta_domain}/api/v1/users/{user_id}/factors/{factor_id}/verify"

            response = await client.post(
                url,
                json={"passCode": code},
                headers={
                    "Authorization": f"SSWS {self.okta_client_secret}"
                }
            )

            duration = (time.perf_counter() - start_time) * 1000
            is_valid = response.status_code == 200

            if is_valid:
                logger.info("SMS verification SUCCESS (%.2fms)", duration)
            else:
                logger.warning("SMS verification FAILED (%.2fms): %s",
                             duration, response.text)

            return is_valid

        except Exception as e:
            logger.error("SMS verification error: %s", str(e))
            return False

    async def send_email_code(self, email: str, user_id: str) -> Optional[str]:
        """Send email verification code via Okta.
        
        Args:
            email: User's email address
            user_id: Okta user ID
            
        Returns:
            Transaction ID for verification or None on error
        """
        if not self.okta_domain or not self.okta_client_secret:
            logger.warning("Okta not configured for email MFA")
            return None

        try:
            client = await self._get_http_client()
            url = f"https://{self.okta_domain}/api/v1/users/{user_id}/factors"

            response = await client.post(
                url,
                json={
                    "factorType": "email",
                    "provider": "OKTA",
                    "profile": {
                        "email": email
                    }
                },
                headers={
                    "Authorization": f"SSWS {self.okta_client_secret}"
                }
            )

            if response.status_code == 200:
                data = response.json()
                logger.info("Email code sent to %s", email)
                return data.get("id")
            else:
                logger.error("Email send failed: %s", response.text)
                return None

        except Exception as e:
            logger.error("Email send error: %s", str(e))
            return None

    async def send_push_notification(self, user_id: str, device_id: str) -> Optional[str]:
        """Send push notification via Okta Verify.
        
        Args:
            user_id: Okta user ID
            device_id: Device factor ID
            
        Returns:
            Transaction ID for polling or None on error
        """
        if not self.okta_domain or not self.okta_client_secret:
            logger.warning("Okta not configured for push MFA")
            return None

        try:
            client = await self._get_http_client()
            url = f"https://{self.okta_domain}/api/v1/users/{user_id}/factors/{device_id}/verify"

            response = await client.post(
                url,
                headers={
                    "Authorization": f"SSWS {self.okta_client_secret}"
                }
            )

            if response.status_code == 200:
                data = response.json()
                logger.info("Push notification sent to device %s", device_id)
                return data.get("factorResult")
            else:
                logger.error("Push send failed: %s", response.text)
                return None

        except Exception as e:
            logger.error("Push notification error: %s", str(e))
            return None

    async def two_factor_login_flow(
        self,
        username: str,
        password: str,
        mfa_code: str,
        mfa_type: MFAType = MFAType.TOTP,
        totp_secret: Optional[str] = None
    ) -> tuple[bool, Optional[str]]:
        """Complete two-factor authentication flow.
        
        Args:
            username: User's username
            password: User's password
            mfa_code: MFA verification code
            mfa_type: Type of MFA being used
            totp_secret: TOTP secret (required for TOTP)
            
        Returns:
            Tuple of (success, error_message)
        """
        start_time = time.perf_counter()

        # Step 1: Verify password (placeholder - integrate with your auth system)
        # In production, this would validate against your user database
        if not username or not password:
            return False, "Invalid credentials"

        # Step 2: Verify MFA code
        if mfa_type == MFAType.TOTP:
            if not totp_secret:
                return False, "TOTP secret required"

            is_valid = await self.verify_totp(totp_secret, mfa_code)
            if not is_valid:
                return False, "Invalid TOTP code"

        elif mfa_type == MFAType.SMS:
            # SMS verification via Okta
            # This requires prior SMS send step
            logger.warning("SMS verification requires factor_id from send step")
            return False, "SMS verification not fully implemented in this flow"

        elif mfa_type == MFAType.EMAIL:
            logger.warning("Email verification requires factor_id from send step")
            return False, "Email verification not fully implemented in this flow"

        else:
            return False, f"Unsupported MFA type: {mfa_type}"

        duration = (time.perf_counter() - start_time) * 1000
        logger.info("Two-factor login SUCCESS for %s (%.2fms)", username, duration)

        return True, None

    async def close(self) -> None:
        """Close HTTP client."""
        if self._http_client:
            await self._http_client.aclose()


# Global MFA service instance
_mfa_service: Optional[MFAService] = None


def get_mfa_service() -> MFAService:
    """Get or create global MFA service instance."""
    global _mfa_service
    if _mfa_service is None:
        _mfa_service = MFAService()
    return _mfa_service
