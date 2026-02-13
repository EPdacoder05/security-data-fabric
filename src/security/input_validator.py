"""Input validation with comprehensive attack pattern detection."""

import re
from enum import Enum
from typing import Dict, List, Optional


class ThreatType(Enum):
    """Enumeration of threat types."""

    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    SSRF = "ssrf"
    COMMAND_INJECTION = "command_injection"
    PATH_TRAVERSAL = "path_traversal"


class ValidationResult:
    """Result of input validation."""

    def __init__(self, is_valid: bool, threats: Optional[List[Dict[str, str]]] = None):
        """Initialize validation result.

        Args:
            is_valid: Whether input passed validation
            threats: List of detected threats with type and pattern
        """
        self.is_valid = is_valid
        self.threats = threats or []


class InputValidator:
    """Input validator with comprehensive attack pattern detection.

    Detects SQL injection, XSS, SSRF, command injection, and path traversal
    attacks using pattern matching.
    """

    SQL_INJECTION_PATTERNS = [
        r"(?i)\bUNION\b.*\bSELECT\b",
        r"(?i)\bOR\b\s+\d+\s*=\s*\d+",
        r"(?i)\bEXEC\b\s*\(",
        r"(?i)\bxp_cmdshell\b",
        r"(?i)\bINFORMATION_SCHEMA\b",
        r"(?i)\bDROP\b\s+\bTABLE\b",
        r"(?i)\bINSERT\b\s+\bINTO\b",
        r"(?i)\bDELETE\b\s+\bFROM\b",
        r"(?i)\bUPDATE\b\s+\w+\s+\bSET\b",
        r"(?i)\bSELECT\b.*\bFROM\b",
        r"(?i)\bUNION\b\s+\bALL\b",
        r"--[^\n]*",
        r"/\*.*?\*/",
        r";[\s]*\w+",
        r"(?i)\bCAST\b\s*\(",
        r"(?i)\bCONVERT\b\s*\(",
        r"(?i)\bCHAR\b\s*\(",
        r"(?i)\bNCHAR\b\s*\(",
        r"(?i)\bVARCHAR\b\s*\(",
        r"(?i)\bNVARCHAR\b\s*\(",
    ]

    XSS_PATTERNS = [
        r"(?i)<script[^>]*>",
        r"(?i)</script>",
        r"(?i)javascript:",
        r"(?i)onerror\s*=",
        r"(?i)onload\s*=",
        r"(?i)eval\s*\(",
        r"(?i)document\.cookie",
        r"(?i)<iframe[^>]*>",
        r"(?i)vbscript:",
        r"(?i)onmouseover\s*=",
    ]

    SSRF_PATTERNS = [
        r"(?i)file://",
        r"(?i)dict://",
        r"(?i)gopher://",
        r"(?i)http://169\.254\.169\.254",
        r"(?i)http://metadata",
        r"(?i)http://localhost",
        r"(?i)http://127\.0\.0\.1",
        r"(?i)http://0\.0\.0\.0",
    ]

    COMMAND_INJECTION_PATTERNS = [
        r"\|",
        r"&(?!amp;|lt;|gt;|quot;|#)",
        r";",
        r"\$\(",
        r"`",
        r"&&",
        r"\|\|",
        r"\n\s*\w+",
        r">\s*/",
    ]

    PATH_TRAVERSAL_PATTERNS = [
        r"\.\./",
        r"\.\.",
        r"%2e%2e",
        r"\.\.\\",
        r"%252e%252e",
        r"..;",
    ]

    def __init__(self):
        """Initialize input validator with compiled patterns."""
        self._sql_patterns = [re.compile(p) for p in self.SQL_INJECTION_PATTERNS]
        self._xss_patterns = [re.compile(p) for p in self.XSS_PATTERNS]
        self._ssrf_patterns = [re.compile(p) for p in self.SSRF_PATTERNS]
        self._cmd_patterns = [re.compile(p) for p in self.COMMAND_INJECTION_PATTERNS]
        self._path_patterns = [re.compile(p) for p in self.PATH_TRAVERSAL_PATTERNS]

    def validate(
        self, input_value: str, check_types: Optional[List[ThreatType]] = None
    ) -> ValidationResult:
        """Validate input against specified threat types.

        Args:
            input_value: Input string to validate
            check_types: List of threat types to check. If None, checks all types.

        Returns:
            ValidationResult with detected threats
        """
        if not input_value:
            return ValidationResult(is_valid=True)

        check_types = check_types or list(ThreatType)
        threats = []

        for threat_type in check_types:
            detected = self._check_threat_type(input_value, threat_type)
            threats.extend(detected)

        return ValidationResult(is_valid=len(threats) == 0, threats=threats)

    def _check_threat_type(self, input_value: str, threat_type: ThreatType) -> List[Dict[str, str]]:
        """Check input for specific threat type.

        Args:
            input_value: Input string to check
            threat_type: Type of threat to check for

        Returns:
            List of detected threats
        """
        threats = []

        if threat_type == ThreatType.SQL_INJECTION:
            threats.extend(
                self._check_patterns(input_value, self._sql_patterns, ThreatType.SQL_INJECTION)
            )
        elif threat_type == ThreatType.XSS:
            threats.extend(self._check_patterns(input_value, self._xss_patterns, ThreatType.XSS))
        elif threat_type == ThreatType.SSRF:
            threats.extend(self._check_patterns(input_value, self._ssrf_patterns, ThreatType.SSRF))
        elif threat_type == ThreatType.COMMAND_INJECTION:
            threats.extend(
                self._check_patterns(input_value, self._cmd_patterns, ThreatType.COMMAND_INJECTION)
            )
        elif threat_type == ThreatType.PATH_TRAVERSAL:
            threats.extend(
                self._check_patterns(input_value, self._path_patterns, ThreatType.PATH_TRAVERSAL)
            )

        return threats

    def _check_patterns(
        self, input_value: str, patterns: List[re.Pattern], threat_type: ThreatType
    ) -> List[Dict[str, str]]:
        """Check input against list of patterns.

        Args:
            input_value: Input string to check
            patterns: Compiled regex patterns to match
            threat_type: Type of threat being checked

        Returns:
            List of detected threats
        """
        threats = []

        for pattern in patterns:
            match = pattern.search(input_value)
            if match:
                threats.append(
                    {
                        "type": threat_type.value,
                        "pattern": pattern.pattern,
                        "matched": match.group(0),
                    }
                )

        return threats

    def is_sql_injection(self, input_value: str) -> bool:
        """Check if input contains SQL injection patterns.

        Args:
            input_value: Input string to check

        Returns:
            True if SQL injection detected, False otherwise
        """
        result = self.validate(input_value, [ThreatType.SQL_INJECTION])
        return not result.is_valid

    def is_xss(self, input_value: str) -> bool:
        """Check if input contains XSS patterns.

        Args:
            input_value: Input string to check

        Returns:
            True if XSS detected, False otherwise
        """
        result = self.validate(input_value, [ThreatType.XSS])
        return not result.is_valid

    def is_ssrf(self, input_value: str) -> bool:
        """Check if input contains SSRF patterns.

        Args:
            input_value: Input string to check

        Returns:
            True if SSRF detected, False otherwise
        """
        result = self.validate(input_value, [ThreatType.SSRF])
        return not result.is_valid

    def is_command_injection(self, input_value: str) -> bool:
        """Check if input contains command injection patterns.

        Args:
            input_value: Input string to check

        Returns:
            True if command injection detected, False otherwise
        """
        result = self.validate(input_value, [ThreatType.COMMAND_INJECTION])
        return not result.is_valid

    def is_path_traversal(self, input_value: str) -> bool:
        """Check if input contains path traversal patterns.

        Args:
            input_value: Input string to check

        Returns:
            True if path traversal detected, False otherwise
        """
        result = self.validate(input_value, [ThreatType.PATH_TRAVERSAL])
        return not result.is_valid
