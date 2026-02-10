"""Zero-day security shield with secure deserialization, hashing, and more."""
import logging
import secrets
import hashlib
import hmac
import json
import pickle
import unicodedata
from typing import Any, Dict, List, Optional
from datetime import datetime, timedelta
import re

import bleach

logger = logging.getLogger(__name__)


class SecureDeserializer:
    """Secure deserialization to prevent arbitrary code execution."""
    
    ALLOWED_CLASSES = {
        'dict', 'list', 'str', 'int', 'float', 'bool', 'NoneType',
        'datetime', 'date', 'time', 'timedelta'
    }
    
    @staticmethod
    def safe_json_loads(data: str) -> Any:
        """Safely load JSON data.
        
        Args:
            data: JSON string
            
        Returns:
            Parsed JSON object
        """
        try:
            return json.loads(data)
        except json.JSONDecodeError as e:
            logger.error("JSON deserialization failed: %s", str(e))
            raise ValueError("Invalid JSON data")
    
    @staticmethod
    def safe_pickle_loads(data: bytes, allowed_classes: Optional[set] = None) -> Any:
        """Safely load pickle data (DANGEROUS - use JSON instead when possible).
        
        Args:
            data: Pickled bytes
            allowed_classes: Set of allowed class names
            
        Returns:
            Unpickled object
            
        Raises:
            ValueError: If unsafe class detected
        """
        if allowed_classes is None:
            allowed_classes = SecureDeserializer.ALLOWED_CLASSES
        
        # WARNING: This is a simplified safety check
        # In production, avoid pickle entirely or use restricted unpickler
        logger.warning("Using pickle deserialization - consider JSON instead")
        
        try:
            obj = pickle.loads(data)
            class_name = type(obj).__name__
            
            if class_name not in allowed_classes:
                raise ValueError(f"Unsafe class in pickle: {class_name}")
            
            return obj
        except Exception as e:
            logger.error("Pickle deserialization failed: %s", str(e))
            raise ValueError("Invalid pickle data")


class SecureHasher:
    """Secure hashing with constant-time comparison."""
    
    @staticmethod
    def hash_password(password: str, salt: Optional[bytes] = None) -> tuple[str, str]:
        """Hash password with PBKDF2.
        
        Args:
            password: Plain text password
            salt: Optional salt (generated if not provided)
            
        Returns:
            Tuple of (hash_hex, salt_hex)
        """
        if salt is None:
            salt = secrets.token_bytes(32)
        
        # PBKDF2 with 100,000 iterations
        hash_bytes = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt,
            100000
        )
        
        return hash_bytes.hex(), salt.hex()
    
    @staticmethod
    def verify_password(password: str, hash_hex: str, salt_hex: str) -> bool:
        """Verify password against hash.
        
        Args:
            password: Plain text password to verify
            hash_hex: Expected hash (hex)
            salt_hex: Salt (hex)
            
        Returns:
            True if password matches
        """
        salt = bytes.fromhex(salt_hex)
        computed_hash, _ = SecureHasher.hash_password(password, salt)
        
        # Constant-time comparison to prevent timing attacks
        return hmac.compare_digest(computed_hash, hash_hex)
    
    @staticmethod
    def hash_token(token: str) -> str:
        """Hash API token for storage.
        
        Args:
            token: API token
            
        Returns:
            SHA-256 hash (hex)
        """
        return hashlib.sha256(token.encode()).hexdigest()
    
    @staticmethod
    def compute_hmac(data: str, key: str) -> str:
        """Compute HMAC for data integrity.
        
        Args:
            data: Data to sign
            key: Secret key
            
        Returns:
            HMAC signature (hex)
        """
        return hmac.new(
            key.encode(),
            data.encode(),
            hashlib.sha256
        ).hexdigest()
    
    @staticmethod
    def verify_hmac(data: str, signature: str, key: str) -> bool:
        """Verify HMAC signature.
        
        Args:
            data: Original data
            signature: HMAC signature to verify
            key: Secret key
            
        Returns:
            True if signature is valid
        """
        expected = SecureHasher.compute_hmac(data, key)
        return hmac.compare_digest(signature, expected)


class SecureRandom:
    """Cryptographically secure random generation."""
    
    @staticmethod
    def generate_token(length: int = 32) -> str:
        """Generate secure random token.
        
        Args:
            length: Token length in bytes
            
        Returns:
            URL-safe token
        """
        return secrets.token_urlsafe(length)
    
    @staticmethod
    def generate_api_key() -> str:
        """Generate API key.
        
        Returns:
            64-character API key
        """
        return secrets.token_urlsafe(48)  # 64 chars base64
    
    @staticmethod
    def generate_secure_int(min_val: int = 0, max_val: int = 1000000) -> int:
        """Generate cryptographically secure random integer.
        
        Args:
            min_val: Minimum value
            max_val: Maximum value
            
        Returns:
            Random integer
        """
        return secrets.randbelow(max_val - min_val + 1) + min_val


class SecureSession:
    """Secure session management."""
    
    def __init__(self, session_timeout_minutes: int = 30) -> None:
        """Initialize secure session manager.
        
        Args:
            session_timeout_minutes: Session timeout duration
        """
        self.session_timeout = timedelta(minutes=session_timeout_minutes)
        self.sessions: Dict[str, Dict[str, Any]] = {}
    
    def create_session(self, user_id: str, data: Dict[str, Any]) -> str:
        """Create new session.
        
        Args:
            user_id: User identifier
            data: Session data
            
        Returns:
            Session ID
        """
        session_id = SecureRandom.generate_token()
        
        self.sessions[session_id] = {
            'user_id': user_id,
            'data': data,
            'created_at': datetime.utcnow(),
            'last_accessed': datetime.utcnow()
        }
        
        logger.info("Session created: user_id=%s", user_id)
        return session_id
    
    def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Get session data.
        
        Args:
            session_id: Session identifier
            
        Returns:
            Session data or None if expired/invalid
        """
        if session_id not in self.sessions:
            return None
        
        session = self.sessions[session_id]
        
        # Check if expired
        if datetime.utcnow() - session['last_accessed'] > self.session_timeout:
            del self.sessions[session_id]
            logger.info("Session expired: %s", session_id)
            return None
        
        # Update last accessed
        session['last_accessed'] = datetime.utcnow()
        
        return session
    
    def revoke_session(self, session_id: str) -> bool:
        """Revoke session.
        
        Args:
            session_id: Session to revoke
            
        Returns:
            True if session was revoked
        """
        if session_id in self.sessions:
            del self.sessions[session_id]
            logger.info("Session revoked: %s", session_id)
            return True
        return False
    
    def cleanup_expired_sessions(self) -> int:
        """Remove expired sessions.
        
        Returns:
            Number of sessions cleaned up
        """
        now = datetime.utcnow()
        expired = [
            sid for sid, session in self.sessions.items()
            if now - session['last_accessed'] > self.session_timeout
        ]
        
        for sid in expired:
            del self.sessions[sid]
        
        if expired:
            logger.info("Cleaned up %d expired sessions", len(expired))
        
        return len(expired)


class SecureHeaders:
    """Security headers for HTTP responses."""
    
    @staticmethod
    def get_security_headers() -> Dict[str, str]:
        """Get recommended security headers.
        
        Returns:
            Dictionary of security headers
        """
        return {
            # Prevent XSS
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'DENY',
            'X-XSS-Protection': '1; mode=block',
            
            # Content Security Policy
            'Content-Security-Policy': (
                "default-src 'self'; "
                "script-src 'self' 'unsafe-inline'; "
                "style-src 'self' 'unsafe-inline'; "
                "img-src 'self' data: https:; "
                "font-src 'self' data:; "
                "connect-src 'self'; "
                "frame-ancestors 'none'"
            ),
            
            # HTTPS enforcement
            'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
            
            # Permissions policy
            'Permissions-Policy': (
                'geolocation=(), microphone=(), camera=()'
            ),
            
            # Referrer policy
            'Referrer-Policy': 'strict-origin-when-cross-origin'
        }


class UnicodeNormalizer:
    """Normalize Unicode to prevent homograph attacks."""
    
    @staticmethod
    def normalize(text: str) -> str:
        """Normalize Unicode text.
        
        Args:
            text: Input text
            
        Returns:
            Normalized text (NFC form)
        """
        return unicodedata.normalize('NFC', text)
    
    @staticmethod
    def is_safe_unicode(text: str) -> bool:
        """Check if text contains potentially dangerous Unicode.
        
        Args:
            text: Text to check
            
        Returns:
            True if safe
        """
        # Check for zero-width characters
        zero_width = ['\u200b', '\u200c', '\u200d', '\ufeff']
        if any(char in text for char in zero_width):
            logger.warning("Zero-width characters detected")
            return False
        
        # Check for RTL override
        rtl_override = ['\u202e', '\u202d']
        if any(char in text for char in rtl_override):
            logger.warning("RTL override characters detected")
            return False
        
        return True


class LogSanitizer:
    """Sanitize logs to prevent log injection."""
    
    @staticmethod
    def sanitize(log_message: str) -> str:
        """Sanitize log message.
        
        Args:
            log_message: Raw log message
            
        Returns:
            Sanitized message
        """
        # Remove newlines and carriage returns
        sanitized = log_message.replace('\n', ' ').replace('\r', ' ')
        
        # Remove ANSI escape codes
        ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
        sanitized = ansi_escape.sub('', sanitized)
        
        return sanitized


class EgressFilter:
    """Filter outbound requests to prevent SSRF."""
    
    BLOCKED_NETWORKS = [
        '127.0.0.0/8',      # Loopback
        '10.0.0.0/8',       # Private
        '172.16.0.0/12',    # Private
        '192.168.0.0/16',   # Private
        '169.254.0.0/16',   # Link-local
        '::1/128',          # IPv6 loopback
        'fe80::/10',        # IPv6 link-local
    ]
    
    @staticmethod
    def is_safe_url(url: str) -> bool:
        """Check if URL is safe for egress.
        
        Args:
            url: URL to check
            
        Returns:
            True if safe
        """
        # Only allow HTTP/HTTPS
        if not url.startswith(('http://', 'https://')):
            logger.warning("Non-HTTP(S) protocol in URL: %s", url)
            return False
        
        # Check for localhost/private IPs
        from src.security.input_validator import get_input_validator
        validator = get_input_validator()
        
        is_safe, _ = validator.validate(url, [validator.AttackType.SSRF])
        return is_safe


class SupplyChainValidator:
    """Validate dependencies for supply chain security."""
    
    @staticmethod
    def verify_checksum(file_path: str, expected_sha256: str) -> bool:
        """Verify file checksum.
        
        Args:
            file_path: Path to file
            expected_sha256: Expected SHA-256 hash
            
        Returns:
            True if checksum matches
        """
        sha256_hash = hashlib.sha256()
        
        try:
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b''):
                    sha256_hash.update(chunk)
            
            computed = sha256_hash.hexdigest()
            matches = hmac.compare_digest(computed, expected_sha256)
            
            if not matches:
                logger.error(
                    "Checksum mismatch: file=%s, expected=%s, got=%s",
                    file_path,
                    expected_sha256,
                    computed
                )
            
            return matches
            
        except FileNotFoundError:
            logger.error("File not found: %s", file_path)
            return False


# Global instances
_secure_session: Optional[SecureSession] = None


def get_secure_session() -> SecureSession:
    """Get or create global secure session manager."""
    global _secure_session
    if _secure_session is None:
        _secure_session = SecureSession()
    return _secure_session
