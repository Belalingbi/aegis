import pytest
from aegis.modules.fuzz import normalize_http_target


def test_normalize_http_target_valid():
    assert normalize_http_target("example.com") == "https://example.com"
    assert normalize_http_target("http://target.local:8080/") == "http://target.local:8080"
    assert normalize_http_target("https://secure.org/api/") == "https://secure.org/api"


def test_normalize_http_target_invalid():
    assert normalize_http_target("") is None
    assert normalize_http_target("ftp://ftp.example.com") is None
    assert normalize_http_target("file:///etc/passwd") is None
