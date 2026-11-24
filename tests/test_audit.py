import pytest
from aegis.modules.audit import calculate_header_score, run_audit


def test_calculate_header_score_perfect():
    headers = {
        "Strict-Transport-Security": "max-age=31536000",
        "Content-Security-Policy": "default-src 'self'",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "no-referrer",
        "Permissions-Policy": "geolocation=()",
    }
    score, grade = calculate_header_score(headers)
    assert score == 100
    assert grade == "A+"


def test_calculate_header_score_poor():
    headers = {
        "Strict-Transport-Security": "ABSENT",
        "Content-Security-Policy": "ABSENT",
        "X-Frame-Options": "ABSENT",
        "X-Content-Type-Options": "ABSENT",
        "Referrer-Policy": "ABSENT",
        "Permissions-Policy": "ABSENT",
    }
    score, grade = calculate_header_score(headers)
    assert score == 0
    assert grade == "F"


def test_audit_scheme_rejection():
    # Rejet des protocoles non autorisés (file, ftp, etc.)
    result = run_audit("file:///etc/passwd")
    assert result["headers"] == {}
    assert result["cves"] == []
