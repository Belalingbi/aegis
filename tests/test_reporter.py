import json
from pathlib import Path
import pytest
from aegis.modules.reporter import (
    sanitize_filename_component,
    generate_html_report,
    generate_markdown_report,
    save_report,
)


def test_sanitize_filename_component():
    # Protection contre le path traversal
    assert ".." not in sanitize_filename_component("../../etc/passwd")
    assert "/" not in sanitize_filename_component("http://example.com/api")
    assert "\\" not in sanitize_filename_component("c:\\windows\\system32")


def test_html_report_xss_protection():
    malicious_payload = {
        "tool": "AEGIS",
        "module": "audit",
        "target": "<script>alert('XSS')</script>",
        "timestamp": "2026-11-24T12:00:00Z",
        "results": {"server": "<img src=x onerror=alert(1)>"},
    }
    html = generate_html_report(malicious_payload)

    # Vérification de la présence de la CSP
    assert "Content-Security-Policy" in html
    assert "default-src 'none'" in html

    # Vérification que le script brut est neutralisé
    assert "<script>alert('XSS')</script>" not in html
    assert "&lt;script&gt;alert(&#x27;XSS&#x27;)&lt;/script&gt;" in html or "\\u003c" in html


def test_save_report_json(tmp_path: Path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    res = save_report("test_module", "127.0.0.1", {"status": "ok"}, output_format="json")
    assert res is not None
    assert res.exists()
    assert res.suffix == ".json"

    data = json.loads(res.read_text(encoding="utf-8"))
    assert data["module"] == "test_module"
    assert data["results"]["status"] == "ok"
