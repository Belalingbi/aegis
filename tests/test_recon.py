import pytest
from aegis.modules.recon import parse_ports, scan_port


def test_parse_ports_valid_simple():
    ports = parse_ports("22,80,443")
    assert ports == [22, 80, 443]


def test_parse_ports_with_ranges():
    ports = parse_ports("22,80-83,443")
    assert ports == [22, 80, 81, 82, 83, 443]


def test_parse_ports_deduplication():
    ports = parse_ports("80,80,80-82")
    assert ports == [80, 81, 82]


def test_parse_ports_invalid():
    assert parse_ports("") is None
    assert parse_ports("abc") is None
    assert parse_ports("0,80") is None
    assert parse_ports("65536") is None
    assert parse_ports("100-50") is None


def test_scan_port_closed():
    # Test scan_port sur une adresse locale fermée ou un port improbable
    port, status, banner = scan_port("127.0.0.1", 65534, timeout=0.2)
    assert port == 65534
    assert status in {"OUVERT", "FERMÉ"}
