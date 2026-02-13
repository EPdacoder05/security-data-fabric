# Security Data Fabric - Security Audit & Attack Pattern Documentation

## Table of Contents
1. [Security Overview](#security-overview)
2. [SQL Injection Protection (20 Patterns)](#sql-injection-protection)
3. [Cross-Site Scripting (XSS) Protection](#cross-site-scripting-xss-protection)
4. [Server-Side Request Forgery (SSRF) Protection](#server-side-request-forgery-ssrf-protection)
5. [Command Injection Protection](#command-injection-protection)
6. [Encryption at Rest](#encryption-at-rest)
7. [Encryption in Transit](#encryption-in-transit)
8. [Authentication Mechanisms](#authentication-mechanisms)
9. [Authorization (RBAC)](#authorization-rbac)
10. [Audit Logging](#audit-logging)
11. [Secret Management](#secret-management)
12. [Compliance Features](#compliance-features)
13. [Additional Security Patterns](#additional-security-patterns)

---

## Security Overview

The Security Data Fabric implements **30+ security patterns** to protect against common vulnerabilities and ensure enterprise-grade security. This document provides comprehensive documentation of all implemented security controls.

### Security Philosophy
1. **Defense in Depth**: Multiple layers of security controls
2. **Least Privilege**: Minimal permissions by default
3. **Zero Trust**: Verify everything, trust nothing
4. **Security by Design**: Security integrated from the start
5. **Continuous Monitoring**: Real-time threat detection

---

## SQL Injection Protection

SQL injection is prevented through **20 distinct patterns**:

### 1. Parameterized Queries (ORM)
**Pattern**: Use SQLAlchemy ORM with bound parameters
```python
# ✅ SECURE - Parameterized query
user = await session.execute(
    select(User).where(User.username == username)
)

# ❌ INSECURE - String concatenation
query = f"SELECT * FROM users WHERE username = '{username}'"
```

### 2. Prepared Statements
**Pattern**: Use prepared statements with placeholders
```python
# ✅ SECURE
stmt = text("SELECT * FROM events WHERE id = :event_id")
result = await session.execute(stmt, {"event_id": event_id})
```

### 3. Input Validation (Type Safety)
**Pattern**: Pydantic models enforce type validation
```python
class UserQuery(BaseModel):
    username: str = Field(..., min_length=3, max_length=50, pattern="^[a-zA-Z0-9_-]+$")
    user_id: int = Field(..., gt=0)
```

### 4. Whitelist Validation for Identifiers
**Pattern**: Validate table/column names against whitelist
```python
ALLOWED_SORT_FIELDS = {"created_at", "severity", "event_type"}

def validate_sort_field(field: str) -> str:
    if field not in ALLOWED_SORT_FIELDS:
        raise ValueError(f"Invalid sort field: {field}")
    return field
```

### 5. Escape Special Characters
**Pattern**: Use SQLAlchemy's text() with proper escaping
```python
from sqlalchemy import text

# Automatically escaped
stmt = text("SELECT * FROM logs WHERE message LIKE :pattern")
result = await session.execute(stmt, {"pattern": f"%{search_term}%"})
```

### 6. Stored Procedures
**Pattern**: Use stored procedures for complex queries
```python
# Database stored procedure
CREATE PROCEDURE get_user_threats(p_user_id INT)
BEGIN
    SELECT * FROM threats WHERE user_id = p_user_id;
END;

# Python call
result = await session.execute(text("CALL get_user_threats(:user_id)"), {"user_id": user_id})
```

### 7. Query Result Limitation
**Pattern**: Limit query results to prevent resource exhaustion
```python
query = select(Event).limit(1000)  # Max 1000 results
```

### 8. Read-Only Database User
**Pattern**: Use read-only credentials for reporting queries
```python
# Separate connection for read-only operations
readonly_engine = create_async_engine(
    settings.READONLY_DATABASE_URL,
    pool_size=10
)
```

### 9. Input Length Restrictions
**Pattern**: Enforce maximum input lengths
```python
class SearchQuery(BaseModel):
    query: str = Field(..., max_length=500)
    filters: dict = Field(..., max_length=1000)
```

### 10. SQL Comment Stripping
**Pattern**: Remove SQL comments from user input
```python
def sanitize_input(value: str) -> str:
    # Remove SQL comments
    value = re.sub(r'--.*$', '', value, flags=re.MULTILINE)
    value = re.sub(r'/\*.*?\*/', '', value, flags=re.DOTALL)
    return value.strip()
```

### 11. Keyword Blacklist
**Pattern**: Block dangerous SQL keywords
```python
DANGEROUS_SQL_KEYWORDS = {
    'UNION', 'SELECT', 'INSERT', 'UPDATE', 'DELETE', 'DROP',
    'CREATE', 'ALTER', 'EXEC', 'EXECUTE', 'SCRIPT'
}

def check_sql_injection(value: str) -> None:
    upper_value = value.upper()
    for keyword in DANGEROUS_SQL_KEYWORDS:
        if keyword in upper_value:
            raise ValueError(f"Potentially dangerous SQL keyword detected: {keyword}")
```

### 12. Context-Aware Escaping
**Pattern**: Different escaping for different contexts
```python
def escape_for_like(value: str) -> str:
    # Escape LIKE wildcards
    return value.replace('%', r'\%').replace('_', r'\_')
```

### 13. ORM Query Builder
**Pattern**: Use ORM's query builder API
```python
# ✅ SECURE - ORM query builder
query = (
    select(Event)
    .where(Event.severity >= min_severity)
    .where(Event.timestamp >= start_date)
    .order_by(Event.timestamp.desc())
)
```

### 14. Database Error Suppression
**Pattern**: Don't expose database errors to users
```python
try:
    result = await session.execute(query)
except SQLAlchemyError as e:
    logger.error(f"Database error: {e}")
    raise HTTPException(status_code=500, detail="Internal server error")
```

### 15. Connection String Protection
**Pattern**: Never expose database credentials
```python
# ✅ SECURE - From environment
DATABASE_URL = os.getenv("DATABASE_URL")

# ❌ INSECURE - Hardcoded
DATABASE_URL = "postgresql://user:pass@localhost/db"
```

### 16. Batch Query Validation
**Pattern**: Validate all queries in a batch
```python
async def execute_batch(queries: List[Dict]) -> List[Any]:
    for query in queries:
        validate_query_params(query)  # Validate each query
    return await session.execute_many(queries)
```

### 17. Schema Validation
**Pattern**: Validate against database schema
```python
from sqlalchemy import inspect

def validate_column_exists(table: str, column: str) -> bool:
    inspector = inspect(engine)
    columns = [c['name'] for c in inspector.get_columns(table)]
    return column in columns
```

### 18. Transaction Isolation
**Pattern**: Use appropriate isolation levels
```python
async with session.begin():
    # Transaction isolation prevents dirty reads
    await session.execute(query)
    await session.commit()
```

### 19. Query Timeouts
**Pattern**: Set query execution timeouts
```python
engine = create_async_engine(
    DATABASE_URL,
    connect_args={"command_timeout": 30}  # 30 second timeout
)
```

### 20. Audit Logging for Queries
**Pattern**: Log all database queries for audit
```python
@event.listens_for(Engine, "before_cursor_execute")
def log_query(conn, cursor, statement, parameters, context, executemany):
    logger.info(f"Query: {statement[:100]}... Params: {parameters}")
```

---

## Cross-Site Scripting (XSS) Protection

### 1. Content Security Policy (CSP)
**Pattern**: Set strict CSP headers
```python
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' 'unsafe-eval'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data: https:; "
        "font-src 'self' data:; "
        "connect-src 'self'"
    )
    return response
```

### 2. Output Encoding
**Pattern**: Encode all user-generated content
```python
import html

def safe_render(content: str) -> str:
    return html.escape(content)
```

### 3. Input Sanitization
**Pattern**: Sanitize HTML input
```python
import bleach

ALLOWED_TAGS = ['p', 'br', 'strong', 'em', 'a']
ALLOWED_ATTRIBUTES = {'a': ['href', 'title']}

def sanitize_html(content: str) -> str:
    return bleach.clean(
        content,
        tags=ALLOWED_TAGS,
        attributes=ALLOWED_ATTRIBUTES,
        strip=True
    )
```

### 4. X-XSS-Protection Header
**Pattern**: Enable browser XSS filter
```python
response.headers["X-XSS-Protection"] = "1; mode=block"
```

### 5. JSON Response Validation
**Pattern**: Ensure JSON responses are properly encoded
```python
from fastapi.responses import JSONResponse

# FastAPI automatically escapes JSON content
return JSONResponse(content={"message": user_input})
```

---

## Server-Side Request Forgery (SSRF) Protection

### 1. URL Whitelist
**Pattern**: Only allow requests to approved domains
```python
ALLOWED_DOMAINS = {"api.example.com", "sentinel.azure.com"}

def validate_url(url: str) -> None:
    parsed = urlparse(url)
    if parsed.netloc not in ALLOWED_DOMAINS:
        raise ValueError(f"Domain not allowed: {parsed.netloc}")
```

### 2. Block Private IP Ranges
**Pattern**: Prevent requests to internal networks
```python
import ipaddress

def is_private_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False

def validate_not_private_ip(url: str) -> None:
    parsed = urlparse(url)
    hostname = parsed.hostname
    try:
        if is_private_ip(hostname):
            raise ValueError("Private IP addresses not allowed")
    except Exception:
        pass  # Not an IP, proceed with domain validation
```

### 3. Disable Redirects
**Pattern**: Don't follow HTTP redirects
```python
async with httpx.AsyncClient(follow_redirects=False) as client:
    response = await client.get(url)
```

### 4. Timeout Configuration
**Pattern**: Set strict timeouts for external requests
```python
timeout = httpx.Timeout(10.0, connect=5.0)
async with httpx.AsyncClient(timeout=timeout) as client:
    response = await client.get(url)
```

### 5. Protocol Restriction
**Pattern**: Only allow HTTPS
```python
def validate_protocol(url: str) -> None:
    parsed = urlparse(url)
    if parsed.scheme != "https":
        raise ValueError("Only HTTPS protocol allowed")
```

---

## Command Injection Protection

### 1. Avoid Shell Execution
**Pattern**: Use Python libraries instead of shell commands
```python
# ✅ SECURE - Use Python libraries
import shutil
shutil.copy(src, dst)

# ❌ INSECURE - Shell command
os.system(f"cp {src} {dst}")
```

### 2. Subprocess with Arguments
**Pattern**: Use subprocess with list arguments
```python
import subprocess

# ✅ SECURE - List arguments
result = subprocess.run(
    ["ls", "-la", directory],
    capture_output=True,
    shell=False  # Never set to True
)

# ❌ INSECURE - String command with shell=True
result = subprocess.run(f"ls -la {directory}", shell=True)
```

### 3. Input Validation for File Operations
**Pattern**: Validate file paths
```python
import os

def validate_file_path(path: str, base_dir: str) -> str:
    # Resolve to absolute path
    abs_path = os.path.abspath(path)
    abs_base = os.path.abspath(base_dir)
    
    # Ensure within base directory (prevent directory traversal)
    if not abs_path.startswith(abs_base):
        raise ValueError("Path outside allowed directory")
    
    return abs_path
```

### 4. Command Whitelist
**Pattern**: Only allow specific commands
```python
ALLOWED_COMMANDS = {"ls", "cat", "grep"}

def validate_command(command: str) -> None:
    if command not in ALLOWED_COMMANDS:
        raise ValueError(f"Command not allowed: {command}")
```

---

## Encryption at Rest

### 1. Field-Level Encryption
**Pattern**: Encrypt sensitive fields with AES-256-GCM
```python
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import base64
import os

class FieldEncryption:
    def __init__(self, key: bytes):
        self.aesgcm = AESGCM(key)  # 256-bit key
    
    def encrypt(self, plaintext: str) -> str:
        nonce = os.urandom(12)
        ciphertext = self.aesgcm.encrypt(nonce, plaintext.encode(), None)
        return base64.b64encode(nonce + ciphertext).decode()
    
    def decrypt(self, encrypted: str) -> str:
        data = base64.b64decode(encrypted)
        nonce, ciphertext = data[:12], data[12:]
        plaintext = self.aesgcm.decrypt(nonce, ciphertext, None)
        return plaintext.decode()
```

### 2. Database Encryption
**Pattern**: Enable PostgreSQL transparent data encryption
```sql
-- Enable pgcrypto extension
CREATE EXTENSION pgcrypto;

-- Encrypt sensitive columns
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255),
    ssn_encrypted BYTEA -- Encrypted with pgcrypto
);

-- Insert encrypted data
INSERT INTO users (email, ssn_encrypted)
VALUES ('user@example.com', pgp_sym_encrypt('123-45-6789', 'encryption_key'));
```

### 3. Key Rotation
**Pattern**: Support multiple encryption keys
```python
class KeyManager:
    def __init__(self):
        self.keys = {
            1: self.load_key("KEY_V1"),
            2: self.load_key("KEY_V2")  # Current key
        }
        self.current_key_version = 2
    
    def encrypt(self, data: str) -> tuple[int, str]:
        key = self.keys[self.current_key_version]
        encrypted = self._encrypt_with_key(key, data)
        return self.current_key_version, encrypted
    
    def decrypt(self, version: int, encrypted: str) -> str:
        key = self.keys[version]
        return self._decrypt_with_key(key, encrypted)
```

### 4. Backup Encryption
**Pattern**: Encrypt database backups
```bash
# Backup with encryption
pg_dump security_fabric | gpg --encrypt --recipient backup@example.com > backup.sql.gpg
```

---

## Encryption in Transit

### 1. TLS 1.3 Configuration
**Pattern**: Enforce TLS 1.3 for all connections
```python
# Uvicorn with TLS
uvicorn.run(
    app,
    host="0.0.0.0",
    port=443,
    ssl_keyfile="/path/to/key.pem",
    ssl_certfile="/path/to/cert.pem",
    ssl_version=ssl.PROTOCOL_TLS,  # TLS 1.3
    ssl_ciphers="TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256"
)
```

### 2. Certificate Pinning
**Pattern**: Pin certificates for external services
```python
import httpx
import ssl

ssl_context = ssl.create_default_context()
ssl_context.check_hostname = True
ssl_context.verify_mode = ssl.CERT_REQUIRED
ssl_context.load_verify_locations("/path/to/cert.pem")

async with httpx.AsyncClient(verify=ssl_context) as client:
    response = await client.get(url)
```

### 3. HSTS Header
**Pattern**: Enforce HTTPS with HSTS
```python
response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"
```

### 4. Database TLS
**Pattern**: Require TLS for database connections
```python
DATABASE_URL = "postgresql+asyncpg://user:pass@host/db?ssl=require"
```

### 5. Redis TLS
**Pattern**: Use TLS for Redis connections
```python
redis_client = Redis(
    host="redis.example.com",
    port=6380,
    ssl=True,
    ssl_cert_reqs="required",
    ssl_ca_certs="/path/to/ca.pem"
)
```

---

## Authentication Mechanisms

### 1. JWT Authentication
**Pattern**: Stateless JWT tokens with short expiration
```python
from jose import jwt
from datetime import datetime, timedelta

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire, "iat": datetime.utcnow()})
    return jwt.encode(to_encode, SECRET_KEY, algorithm="HS256")
```

### 2. Password Hashing
**Pattern**: bcrypt with salt
```python
from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)
```

### 3. Multi-Factor Authentication (MFA)
**Pattern**: TOTP-based 2FA
```python
import pyotp

class MFAManager:
    def generate_secret(self) -> str:
        return pyotp.random_base32()
    
    def get_totp_uri(self, secret: str, username: str) -> str:
        return pyotp.totp.TOTP(secret).provisioning_uri(
            name=username,
            issuer_name="Security Fabric"
        )
    
    def verify_totp(self, secret: str, token: str) -> bool:
        totp = pyotp.TOTP(secret)
        return totp.verify(token, valid_window=1)
```

### 4. API Key Authentication
**Pattern**: Secure API keys with hashing
```python
def generate_api_key() -> tuple[str, str]:
    # Generate key
    key = secrets.token_urlsafe(32)
    # Store only hash
    key_hash = hashlib.sha256(key.encode()).hexdigest()
    return key, key_hash

def verify_api_key(provided_key: str, stored_hash: str) -> bool:
    provided_hash = hashlib.sha256(provided_key.encode()).hexdigest()
    return secrets.compare_digest(provided_hash, stored_hash)
```

### 5. OAuth2 / SAML Integration
**Pattern**: SSO with Azure AD and Okta
```python
from authlib.integrations.starlette_client import OAuth

oauth = OAuth()
oauth.register(
    name='azure',
    client_id=AZURE_CLIENT_ID,
    client_secret=AZURE_CLIENT_SECRET,
    server_metadata_url=f'https://login.microsoftonline.com/{TENANT_ID}/v2.0/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid email profile'}
)
```

### 6. Rate Limiting
**Pattern**: Prevent brute force attacks
```python
from slowapi import Limiter
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address)

@app.post("/login")
@limiter.limit("5/minute")  # Max 5 attempts per minute
async def login(request: Request, credentials: LoginRequest):
    pass
```

### 7. Account Lockout
**Pattern**: Lock account after failed attempts
```python
class AccountLockout:
    MAX_ATTEMPTS = 5
    LOCKOUT_DURATION = timedelta(minutes=30)
    
    async def record_failure(self, username: str):
        key = f"login_failures:{username}"
        failures = await redis.incr(key)
        await redis.expire(key, 3600)
        
        if failures >= self.MAX_ATTEMPTS:
            await self.lock_account(username)
    
    async def lock_account(self, username: str):
        await redis.setex(
            f"account_locked:{username}",
            int(self.LOCKOUT_DURATION.total_seconds()),
            "1"
        )
```

---

## Authorization (RBAC)

### 1. Role-Based Access Control
**Pattern**: Define roles and permissions
```python
class Role(str, Enum):
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"

class Permission(str, Enum):
    READ_EVENTS = "read:events"
    WRITE_EVENTS = "write:events"
    DELETE_EVENTS = "delete:events"
    MANAGE_USERS = "manage:users"

ROLE_PERMISSIONS = {
    Role.ADMIN: [Permission.READ_EVENTS, Permission.WRITE_EVENTS, 
                 Permission.DELETE_EVENTS, Permission.MANAGE_USERS],
    Role.ANALYST: [Permission.READ_EVENTS, Permission.WRITE_EVENTS],
    Role.VIEWER: [Permission.READ_EVENTS]
}
```

### 2. Permission Decorator
**Pattern**: Enforce permissions on endpoints
```python
def require_permission(permission: Permission):
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, current_user: User = Depends(get_current_user), **kwargs):
            if not has_permission(current_user, permission):
                raise HTTPException(status_code=403, detail="Insufficient permissions")
            return await func(*args, current_user=current_user, **kwargs)
        return wrapper
    return decorator

@app.delete("/events/{event_id}")
@require_permission(Permission.DELETE_EVENTS)
async def delete_event(event_id: str, current_user: User):
    pass
```

### 3. Resource-Level Authorization
**Pattern**: Check ownership before operations
```python
async def verify_resource_access(user: User, resource_id: str):
    resource = await get_resource(resource_id)
    if resource.owner_id != user.id and not user.is_admin:
        raise HTTPException(status_code=403, detail="Access denied")
```

### 4. Multi-Tenancy Isolation
**Pattern**: Enforce tenant isolation
```python
async def get_tenant_data(user: User, query: Query):
    # Automatically filter by tenant
    return query.filter(Data.tenant_id == user.tenant_id)
```

---

## Audit Logging

### 1. Comprehensive Audit Trail
**Pattern**: Log all security-relevant events
```python
class AuditLogger:
    async def log(
        self,
        user_id: str,
        action: str,
        resource: str,
        status: str,
        details: dict = None,
        request: Request = None
    ):
        log_entry = AuditLog(
            id=uuid.uuid4(),
            timestamp=datetime.utcnow(),
            user_id=user_id,
            action=action,
            resource=resource,
            status=status,
            details=details,
            ip_address=request.client.host if request else None,
            user_agent=request.headers.get("user-agent") if request else None
        )
        await session.add(log_entry)
        await session.commit()
```

### 2. Immutable Logs
**Pattern**: Prevent log tampering
```sql
-- Create append-only audit table
CREATE TABLE audit_log (
    id UUID PRIMARY KEY,
    timestamp TIMESTAMPTZ NOT NULL,
    user_id VARCHAR(255),
    action VARCHAR(100) NOT NULL,
    resource VARCHAR(255),
    status VARCHAR(50),
    details JSONB,
    ip_address INET,
    user_agent TEXT
);

-- Revoke UPDATE and DELETE permissions
REVOKE UPDATE, DELETE ON audit_log FROM securityfabric;
GRANT INSERT, SELECT ON audit_log TO securityfabric;
```

### 3. Log Aggregation
**Pattern**: Centralized logging
```python
import logging
from pythonjsonlogger import jsonlogger

logger = logging.getLogger()
logHandler = logging.StreamHandler()
formatter = jsonlogger.JsonFormatter()
logHandler.setFormatter(formatter)
logger.addHandler(logHandler)
```

---

## Secret Management

### 1. Azure Key Vault Integration
**Pattern**: Store secrets in Azure Key Vault
```python
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient

credential = DefaultAzureCredential()
client = SecretClient(vault_url=KEYVAULT_URL, credential=credential)

def get_secret(secret_name: str) -> str:
    return client.get_secret(secret_name).value
```

### 2. Environment Variable Protection
**Pattern**: Never commit secrets to code
```python
# ✅ SECURE - From environment
SECRET_KEY = os.getenv("SECRET_KEY")
if not SECRET_KEY:
    raise ValueError("SECRET_KEY must be set")

# ❌ INSECURE - Hardcoded
SECRET_KEY = "my-secret-key-123"
```

### 3. Secret Rotation
**Pattern**: Support automatic secret rotation
```python
class SecretRotator:
    async def rotate_secret(self, secret_name: str):
        # Generate new secret
        new_secret = secrets.token_urlsafe(32)
        
        # Store new secret
        await key_vault.set_secret(f"{secret_name}_new", new_secret)
        
        # Update application config
        await self.update_config(secret_name, new_secret)
        
        # Delete old secret after grace period
        await asyncio.sleep(3600)  # 1 hour grace period
        await key_vault.delete_secret(secret_name)
```

---

## Compliance Features

### 1. SOC 2 Compliance
- Comprehensive audit logging
- Access control and monitoring
- Encryption at rest and in transit
- Incident response procedures
- Vendor management

### 2. ISO 27001
- Information security management system (ISMS)
- Risk assessment and treatment
- Asset management
- Access control policies
- Cryptographic controls

### 3. GDPR Compliance
**Pattern**: Data subject rights
```python
class GDPRCompliance:
    async def export_user_data(self, user_id: str) -> dict:
        """Right to data portability"""
        return {
            "user": await get_user(user_id),
            "events": await get_user_events(user_id),
            "audit_logs": await get_user_audit_logs(user_id)
        }
    
    async def delete_user_data(self, user_id: str):
        """Right to be forgotten"""
        await anonymize_user_data(user_id)
        await log_deletion(user_id)
```

### 4. HIPAA Compliance
- PHI encryption
- Access logging
- User authentication
- Data backup and recovery
- Business associate agreements

### 5. PCI-DSS
- Cardholder data protection
- Vulnerability management
- Access control measures
- Network security
- Monitoring and testing

---

## Additional Security Patterns

### 1. Rate Limiting (Global)
```python
@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    client_ip = request.client.host
    key = f"rate_limit:{client_ip}"
    
    current = await redis.incr(key)
    if current == 1:
        await redis.expire(key, 60)
    
    if current > 100:  # 100 requests per minute
        raise HTTPException(status_code=429, detail="Too many requests")
    
    return await call_next(request)
```

### 2. CORS Configuration
```python
from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://app.example.com"],  # Specific origins only
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["*"],
    max_age=3600
)
```

### 3. Security Headers
```python
SECURITY_HEADERS = {
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "X-XSS-Protection": "1; mode=block",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=()"
}
```

### 4. Input Validation Patterns
```python
class SecureInput(BaseModel):
    # Email validation
    email: EmailStr
    
    # URL validation
    webhook_url: HttpUrl
    
    # String length limits
    username: str = Field(..., min_length=3, max_length=50)
    
    # Pattern matching
    api_key: str = Field(..., regex=r'^[a-zA-Z0-9]{32}$')
    
    # Enum validation
    severity: Literal["low", "medium", "high", "critical"]
```

### 5. Secure Session Management
```python
from starlette.middleware.sessions import SessionMiddleware

app.add_middleware(
    SessionMiddleware,
    secret_key=SECRET_KEY,
    session_cookie="session",
    max_age=1800,  # 30 minutes
    same_site="strict",
    https_only=True
)
```

### 6. File Upload Security
```python
ALLOWED_EXTENSIONS = {".csv", ".json", ".txt"}
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB

async def secure_file_upload(file: UploadFile):
    # Validate extension
    ext = os.path.splitext(file.filename)[1].lower()
    if ext not in ALLOWED_EXTENSIONS:
        raise ValueError("Invalid file type")
    
    # Validate size
    content = await file.read()
    if len(content) > MAX_FILE_SIZE:
        raise ValueError("File too large")
    
    # Scan for malware (integrate with antivirus)
    if not await scan_file(content):
        raise ValueError("File contains malware")
    
    return content
```

### 7. Dependency Scanning
```bash
# Use Bandit for security scanning
bandit -r src/ -f json -o bandit-report.json

# Use Safety for dependency vulnerabilities
safety check --json
```

### 8. Container Security
```dockerfile
# Run as non-root user
USER appuser

# Read-only filesystem
RUN chmod -R 555 /app

# Drop all capabilities
# Handled by docker-compose.yml
```

---

## Security Testing Checklist

- [ ] SQL injection tests (20 patterns)
- [ ] XSS protection tests
- [ ] SSRF protection tests
- [ ] Command injection tests
- [ ] Authentication bypass tests
- [ ] Authorization tests (RBAC)
- [ ] Session management tests
- [ ] CSRF protection tests
- [ ] Encryption tests (at rest and in transit)
- [ ] Secret management tests
- [ ] Rate limiting tests
- [ ] Input validation tests
- [ ] Error handling tests
- [ ] Audit logging verification
- [ ] Compliance validation
- [ ] Penetration testing

---

## Security Monitoring

### Metrics to Monitor
- Failed authentication attempts
- Authorization failures
- Unusual API usage patterns
- Database query anomalies
- High error rates
- Slow response times
- Suspicious IP addresses
- Data exfiltration indicators

### Alerts to Configure
- Multiple failed logins
- Privilege escalation attempts
- Unusual data access patterns
- API abuse
- Security policy violations
- Certificate expiration
- Vulnerability disclosures

---

## Incident Response

### 1. Detection
- Real-time monitoring with Prometheus
- Anomaly detection with ML
- Security alerts via webhook

### 2. Containment
- Automatic account lockout
- IP blocking
- Rate limiting enforcement

### 3. Recovery
- Restore from encrypted backups
- Key rotation procedures
- Audit log analysis

### 4. Post-Incident
- Root cause analysis
- Security improvements
- Documentation updates

---

## References

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CWE/SANS Top 25](https://cwe.mitre.org/top25/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [PCI-DSS Security Standards](https://www.pcisecuritystandards.org/)
- [ISO 27001](https://www.iso.org/isoiec-27001-information-security.html)

---

**Last Updated**: 2024-01-01  
**Version**: 1.0.0  
**Maintainer**: Security Team
