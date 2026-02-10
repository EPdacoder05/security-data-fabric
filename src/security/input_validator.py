"""Input validation with 32 attack pattern detection (SQL, XSS, LDAP, Path Traversal, etc.)."""
import logging
import re
from enum import Enum
from typing import List, Optional, Tuple

logger = logging.getLogger(__name__)


class AttackType(str, Enum):
    """Types of attacks that can be detected."""
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    LDAP_INJECTION = "ldap_injection"
    PATH_TRAVERSAL = "path_traversal"
    COMMAND_INJECTION = "command_injection"
    SSRF = "ssrf"
    XXE = "xxe"
    REDOS = "redos"


class InputValidator:
    """Validate and sanitize user input to prevent injection attacks."""

    # 26 SQL Injection Patterns
    SQL_PATTERNS = [
        r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|EXECUTE)\b)",
        r"(UNION\s+SELECT)",
        r"(--|\#|\/\*|\*\/)",  # SQL comments
        r"(;.*\b(DROP|DELETE|UPDATE|INSERT)\b)",
        r"(\bOR\b.*=.*)",
        r"(\bAND\b.*=.*)",
        r"('|\")\s*(OR|AND)\s*('|\")?\s*('|\")?\s*=\s*('|\")?",
        r"(xp_|sp_|exec|execute)",
        r"(\bINTO\b.*\bOUTFILE\b)",
        r"(\bLOAD_FILE\b)",
        r"(CONCAT\s*\(.*\))",
        r"(CHR\s*\(.*\))",
        r"(CHAR\s*\(.*\))",
        r"(0x[0-9a-fA-F]+)",  # Hexadecimal
        r"(WAITFOR\s+DELAY)",
        r"(BENCHMARK\s*\()",
        r"(SLEEP\s*\()",
        r"(pg_sleep)",
        r"(DBMS_LOCK\.SLEEP)",
        r"(information_schema)",
        r"(sysobjects|syscolumns)",
        r"(\$\$.*\$\$)",  # Dollar quoting
        r"(@@version)",
        r"(CAST\s*\()",
        r"(CONVERT\s*\()",
        r"(SUBSTRING\s*\()"
    ]

    # 10 XSS (Cross-Site Scripting) Patterns
    XSS_PATTERNS = [
        r"(<script[^>]*>.*?</script>)",
        r"(javascript:)",
        r"(onerror\s*=)",
        r"(onload\s*=)",
        r"(onclick\s*=)",
        r"(onmouseover\s*=)",
        r"(<iframe[^>]*>)",
        r"(<embed[^>]*>)",
        r"(<object[^>]*>)",
        r"(data:text/html)"
    ]

    # LDAP Injection Patterns
    LDAP_PATTERNS = [
        r"(\*\s*\))",
        r"(\|\s*\()",
        r"(&\s*\()",
        r"(\(\s*\|)",
        r"(\(\s*&)"
    ]

    # Path Traversal Patterns
    PATH_TRAVERSAL_PATTERNS = [
        r"(\.\./|\.\.\\)",
        r"(\.\.%2[fF])",
        r"(%2e%2e[/\\])",
        r"(/etc/passwd)",
        r"(c:\\windows)",
        r"(/proc/self)"
    ]

    # Command Injection Patterns
    COMMAND_INJECTION_PATTERNS = [
        r"(;|\||&|\$\(|\`)",
        r"(\bnc\b|\bnetcat\b)",
        r"(\bwget\b|\bcurl\b)",
        r"(\bpython\b.*-c)",
        r"(\bperl\b.*-e)",
        r"(\bphp\b.*-r)",
        r"(/bin/(bash|sh|zsh))"
    ]

    # SSRF (Server-Side Request Forgery) Patterns
    SSRF_PATTERNS = [
        r"(localhost|127\.0\.0\.1|0\.0\.0\.0)",
        r"(169\.254\.169\.254)",  # AWS metadata
        r"(::1)",  # IPv6 localhost
        r"(file://|gopher://|dict://)"
    ]

    # XXE (XML External Entity) Patterns
    XXE_PATTERNS = [
        r"(<!ENTITY)",
        r"(<!DOCTYPE.*\[)",
        r"(SYSTEM\s+[\"'])",
        r"(PUBLIC\s+[\"'])"
    ]

    # ReDoS (Regular Expression Denial of Service) Patterns
    REDOS_PATTERNS = [
        r"(.+\*)+",
        r"(.*)+",
        r"(.+)+",
        r"(\w+\*)+\w"
    ]

    def __init__(self) -> None:
        """Initialize input validator."""
        self._compile_patterns()

    def _compile_patterns(self) -> None:
        """Compile regex patterns for performance."""
        self.sql_regexes = [re.compile(p, re.IGNORECASE) for p in self.SQL_PATTERNS]
        self.xss_regexes = [re.compile(p, re.IGNORECASE) for p in self.XSS_PATTERNS]
        self.ldap_regexes = [re.compile(p, re.IGNORECASE) for p in self.LDAP_PATTERNS]
        self.path_traversal_regexes = [re.compile(p, re.IGNORECASE) for p in self.PATH_TRAVERSAL_PATTERNS]
        self.command_injection_regexes = [re.compile(p, re.IGNORECASE) for p in self.COMMAND_INJECTION_PATTERNS]
        self.ssrf_regexes = [re.compile(p, re.IGNORECASE) for p in self.SSRF_PATTERNS]
        self.xxe_regexes = [re.compile(p, re.IGNORECASE) for p in self.XXE_PATTERNS]
        self.redos_regexes = [re.compile(p, re.IGNORECASE) for p in self.REDOS_PATTERNS]

    def validate(self, input_str: str, check_types: Optional[List[AttackType]] = None) -> Tuple[bool, List[str]]:
        """Validate input against attack patterns.
        
        Args:
            input_str: User input to validate
            check_types: Specific attack types to check (default: all)
            
        Returns:
            Tuple of (is_safe, list_of_detected_attacks)
        """
        if not input_str:
            return True, []

        detected_attacks = []

        if check_types is None:
            check_types = list(AttackType)

        # Check SQL Injection
        if AttackType.SQL_INJECTION in check_types:
            for regex in self.sql_regexes:
                if regex.search(input_str):
                    detected_attacks.append(f"SQL Injection: {regex.pattern}")
                    logger.warning("SQL injection detected: pattern=%s, input=%s", regex.pattern, input_str[:100])
                    break

        # Check XSS
        if AttackType.XSS in check_types:
            for regex in self.xss_regexes:
                if regex.search(input_str):
                    detected_attacks.append(f"XSS: {regex.pattern}")
                    logger.warning("XSS detected: pattern=%s, input=%s", regex.pattern, input_str[:100])
                    break

        # Check LDAP Injection
        if AttackType.LDAP_INJECTION in check_types:
            for regex in self.ldap_regexes:
                if regex.search(input_str):
                    detected_attacks.append(f"LDAP Injection: {regex.pattern}")
                    logger.warning("LDAP injection detected: pattern=%s", regex.pattern)
                    break

        # Check Path Traversal
        if AttackType.PATH_TRAVERSAL in check_types:
            for regex in self.path_traversal_regexes:
                if regex.search(input_str):
                    detected_attacks.append(f"Path Traversal: {regex.pattern}")
                    logger.warning("Path traversal detected: pattern=%s", regex.pattern)
                    break

        # Check Command Injection
        if AttackType.COMMAND_INJECTION in check_types:
            for regex in self.command_injection_regexes:
                if regex.search(input_str):
                    detected_attacks.append(f"Command Injection: {regex.pattern}")
                    logger.warning("Command injection detected: pattern=%s", regex.pattern)
                    break

        # Check SSRF
        if AttackType.SSRF in check_types:
            for regex in self.ssrf_regexes:
                if regex.search(input_str):
                    detected_attacks.append(f"SSRF: {regex.pattern}")
                    logger.warning("SSRF detected: pattern=%s", regex.pattern)
                    break

        # Check XXE
        if AttackType.XXE in check_types:
            for regex in self.xxe_regexes:
                if regex.search(input_str):
                    detected_attacks.append(f"XXE: {regex.pattern}")
                    logger.warning("XXE detected: pattern=%s", regex.pattern)
                    break

        # Check ReDoS
        if AttackType.REDOS in check_types:
            for regex in self.redos_regexes:
                try:
                    if regex.search(input_str):
                        detected_attacks.append(f"ReDoS: {regex.pattern}")
                        logger.warning("ReDoS pattern detected")
                        break
                except Exception:
                    # Pattern itself might cause ReDoS
                    pass

        is_safe = len(detected_attacks) == 0

        return is_safe, detected_attacks

    def sanitize_sql(self, input_str: str) -> str:
        """Sanitize input for SQL queries.
        
        Args:
            input_str: Input to sanitize
            
        Returns:
            Sanitized string
        """
        # Escape single quotes
        sanitized = input_str.replace("'", "''")

        # Remove SQL keywords
        for pattern in ["--", "/*", "*/", ";", "xp_", "sp_"]:
            sanitized = sanitized.replace(pattern, "")

        return sanitized

    def sanitize_html(self, input_str: str) -> str:
        """Sanitize input for HTML output (prevent XSS).
        
        Args:
            input_str: Input to sanitize
            
        Returns:
            Sanitized string
        """
        import html
        return html.escape(input_str)

    def sanitize_filename(self, filename: str) -> str:
        """Sanitize filename to prevent path traversal.
        
        Args:
            filename: Filename to sanitize
            
        Returns:
            Safe filename
        """
        # Remove path components
        filename = filename.replace("../", "").replace("..\\", "")
        filename = filename.replace("/", "").replace("\\", "")

        # Remove dangerous characters
        filename = re.sub(r'[<>:"|?*]', '', filename)

        return filename

    def validate_email(self, email: str) -> bool:
        """Validate email address format.
        
        Args:
            email: Email address to validate
            
        Returns:
            True if valid email format
        """
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(pattern, email))

    def validate_url(self, url: str) -> bool:
        """Validate URL format and check for SSRF.
        
        Args:
            url: URL to validate
            
        Returns:
            True if safe URL
        """
        # Check for SSRF patterns
        is_safe, _ = self.validate(url, [AttackType.SSRF])
        if not is_safe:
            return False

        # Check basic URL format
        pattern = r'^https?://'
        return bool(re.match(pattern, url))

    def count_total_patterns(self) -> int:
        """Count total number of attack patterns.
        
        Returns:
            Total pattern count
        """
        return (
            len(self.SQL_PATTERNS) +
            len(self.XSS_PATTERNS) +
            len(self.LDAP_PATTERNS) +
            len(self.PATH_TRAVERSAL_PATTERNS) +
            len(self.COMMAND_INJECTION_PATTERNS) +
            len(self.SSRF_PATTERNS) +
            len(self.XXE_PATTERNS) +
            len(self.REDOS_PATTERNS)
        )


# Global validator instance
_validator: Optional[InputValidator] = None


def get_input_validator() -> InputValidator:
    """Get or create global input validator instance."""
    global _validator
    if _validator is None:
        _validator = InputValidator()
        logger.info("Input validator initialized with %d patterns", _validator.count_total_patterns())
    return _validator
