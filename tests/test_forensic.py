import hashlib
import os
from pathlib import Path
import pytest
from aegis.modules.forensic import (
    calculate_hashes,
    calculate_entropy,
    extract_strings,
    extract_iocs_from_strings,
)


@pytest.fixture
def sample_file(tmp_path: Path):
    file = tmp_path / "sample_forensic.txt"
    content = (
        b"Hello CyberSecurity World! This is a test file for AEGIS forensics.\n"
        b"C2 Server: https://malicious-c2.test/api/endpoint\n"
        b"Victim IP: 198.51.100.42 and contact: admin@targetcorp.internal\n"
    )
    file.write_bytes(content)
    return file


def test_calculate_hashes(sample_file: Path):
    hashes = calculate_hashes(sample_file)
    assert hashes is not None
    data = sample_file.read_bytes()
    assert hashes["md5"] == hashlib.md5(data).hexdigest()
    assert hashes["sha1"] == hashlib.sha1(data).hexdigest()
    assert hashes["sha256"] == hashlib.sha256(data).hexdigest()
    assert hashes["sha512"] == hashlib.sha512(data).hexdigest()


def test_calculate_entropy_zero(tmp_path: Path):
    empty_file = tmp_path / "empty.bin"
    empty_file.write_bytes(b"")
    assert calculate_entropy(empty_file) == 0.0


def test_calculate_entropy_uniform(tmp_path: Path):
    # Fichier avec un seul caractère répété -> entropie nulle (0.0)
    uniform_file = tmp_path / "uniform.bin"
    uniform_file.write_bytes(b"A" * 1024)
    assert calculate_entropy(uniform_file) == 0.0


def test_calculate_entropy_random(tmp_path: Path):
    # Fichier quasi-aléatoire -> entropie proche de 8
    rand_file = tmp_path / "random.bin"
    rand_file.write_bytes(os.urandom(2048))
    entropy = calculate_entropy(rand_file)
    assert 7.0 < entropy <= 8.0


def test_extract_strings_and_iocs(sample_file: Path):
    strings = extract_strings(sample_file, min_len=5)
    assert any("CyberSecurity" in s for s in strings)

    iocs = extract_iocs_from_strings(strings)
    assert "198.51.100.42" in iocs["ips"]
    assert any("malicious-c2.test" in u for u in iocs["urls"])
    assert "admin@targetcorp.internal" in iocs["emails"]
