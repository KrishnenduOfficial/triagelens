"""Adversarial and extreme edge-case tests for indicator extraction utilities."""

import time
import pytest

from src.utils.extraction import (
    extract_domains,
    extract_hashes,
    extract_ips,
    extract_urls,
)


# ---------------------------------------------------------------------------
# 1. ReDoS (Regular Expression Denial of Service) Defenses
# ---------------------------------------------------------------------------

def test_redos_ips_1mb_repeating_partial():
    """1 Megabyte payload of repeating octets must complete in under 1 second without hanging."""
    payload = "999." * 250_000
    start = time.time()
    results = extract_ips(payload)
    duration = time.time() - start

    assert duration < 1.0, f"extract_ips hung for {duration:.2f}s"
    assert results == []


def test_redos_domains_1mb_repeating_partial():
    """1 Megabyte payload of repeating 'a.' patterns must complete in under 1 second without catastrophic backtracking."""
    payload = "a." * 500_000
    start = time.time()
    results = extract_domains(payload)
    duration = time.time() - start

    assert duration < 1.0, f"extract_domains hung for {duration:.2f}s"
    assert results == []


def test_redos_hashes_1mb_repeating_hex():
    """1 Megabyte continuous hex stream must scan in under 1 second without exponential blowup."""
    payload = "f" * 1_000_000
    start = time.time()
    results = extract_hashes(payload)
    duration = time.time() - start

    assert duration < 1.0, f"extract_hashes hung for {duration:.2f}s"


def test_redos_urls_1mb_repeating_slashes():
    """1 Megabyte of repeating URL schemes must process in under 1 second."""
    payload = "http://" * 150_000
    start = time.time()
    results = extract_urls(payload)
    duration = time.time() - start

    assert duration < 1.0, f"extract_urls hung for {duration:.2f}s"
    assert results == []


# ---------------------------------------------------------------------------
# 2. IP Boundary & RFC Validation Gauntlet
# ---------------------------------------------------------------------------

def test_ip_boundary_out_of_range_octets():
    """Strictly reject octets > 255."""
    text = "Connecting to 256.256.256.256 and 999.999.999.999 and 192.168.1.300"
    assert extract_ips(text) == []


def test_ip_boundary_loopback_rejected():
    """Strictly reject 127.0.0.0/8 loopback range."""
    text = "Local tests on 127.0.0.1, 127.0.0.2, and 127.255.255.254"
    assert extract_ips(text) == []


def test_ip_boundary_rfc1918_10_network_rejected():
    """Strictly reject 10.0.0.0/8 private network."""
    text = "Internal node 10.0.0.1 communicating with 10.255.255.254"
    assert extract_ips(text) == []


def test_ip_boundary_rfc1918_192_168_network_rejected():
    """Strictly reject 192.168.0.0/16 private network."""
    text = "Gateway 192.168.1.1 and host 192.168.0.50"
    assert extract_ips(text) == []


def test_ip_boundary_rfc1918_172_network_rejected():
    """Strictly reject 172.16.0.0/12 private network, allow public 172.32+."""
    text = "Private 172.16.0.1 and 172.31.255.254. Public 172.32.0.1"
    ips = extract_ips(text)
    assert "172.16.0.1" not in ips
    assert "172.31.255.254" not in ips
    assert "172.32.0.1" in ips


def test_ip_boundary_multicast_and_broadcast_rejected():
    """Strictly reject multicast (224.0.0.0/4) and broadcast (255.255.255.255)."""
    text = "Multicast 224.0.0.1 and 239.255.255.250 and broadcast 255.255.255.255"
    assert extract_ips(text) == []


def test_ip_boundary_link_local_and_unspecified_rejected():
    """Strictly reject link-local (169.254.0.0/16) and 0.0.0.0."""
    text = "APIPA 169.254.1.1 and default route 0.0.0.0"
    assert extract_ips(text) == []


def test_ip_valid_public_ips_extracted():
    """Routable public IPv4 addresses must be correctly identified and extracted."""
    text = "External C2 at 198.51.100.45 and DNS at 8.8.8.8 and Cloudflare 1.1.1.1"
    ips = extract_ips(text)
    assert ips == ["198.51.100.45", "8.8.8.8", "1.1.1.1"]


# ---------------------------------------------------------------------------
# 3. Domain Obfuscation, Punycode & False-Positive Prevention
# ---------------------------------------------------------------------------

def test_domain_punycode_support():
    """Extract valid Punycode (xn--) internationalized domain names."""
    text = "Phishing domain xn--80akhbyknj4f.com detected with Russian TLD test.xn--p1ai"
    domains = extract_domains(text)
    assert "xn--80akhbyknj4f.com" in domains
    assert "test.xn--p1ai" in domains


def test_domain_file_extension_exclusions():
    """Common executable and data file extensions must not be classified as domains."""
    text = "Executed malware.exe from C:\\Windows\\System32\\driver.sys, log at alert.json and report.csv"
    assert extract_domains(text) == []


def test_domain_ip_addresses_not_extracted_as_domains():
    """IP addresses must never be returned in domain extraction."""
    text = "Alert on 198.51.100.22 and 8.8.8.8"
    assert extract_domains(text) == []


def test_domain_unicode_idn_support():
    """Internationalized domain names in Cyrillic/German must be handled safely."""
    text = "Connecting to münchen.de and русский-домен.рф"
    domains = extract_domains(text)
    assert len(domains) >= 1


# ---------------------------------------------------------------------------
# 4. Hash Obfuscation & Zero-Width Evaders
# ---------------------------------------------------------------------------

def test_hashes_zero_width_space_unobfuscation():
    """Hashes laced with zero-width spaces (\u200b, \u200c, \u200d, \ufeff) must be reconstructed."""
    # SHA-256 with injected zero-width spaces
    obfuscated_hash = (
        "e3b0\u200bc442\u200c98fc\u200d1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\ufeff"
    )
    text = f"Payload hash: {obfuscated_hash}"
    hashes = extract_hashes(text)
    assert "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" in hashes


def test_hashes_valid_md5_sha1_sha256():
    """Extract MD5, SHA-1, and SHA-256 hashes cleanly without collisions."""
    md5 = "44d88612fea8a8f36de82e1278abb02f"
    sha1 = "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12"
    sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    text = f"Samples: MD5={md5}, SHA1={sha1}, SHA256={sha256}"
    extracted = extract_hashes(text)

    assert md5 in extracted
    assert sha1 in extracted
    assert sha256 in extracted


# ---------------------------------------------------------------------------
# 5. Malformed URLs, Port Limits & Credentials
# ---------------------------------------------------------------------------

def test_url_missing_scheme_rejected():
    """Raw paths and domains without http/https schemes are rejected as URLs."""
    text = "Visit evil.com/payload.exe or ftp://evil.com/bad"
    assert extract_urls(text) == []


def test_url_excessive_port_rejected():
    """Reject URLs with port numbers exceeding 65535."""
    text = "Connecting to http://evil.com:999999/malware and http://c2.org:70000/gate"
    assert extract_urls(text) == []


def test_url_valid_ports_and_credentials():
    """Support valid ports and credential injection in URLs."""
    valid_url = "http://admin:P@ssw0rd123@evil.com:8080/c2/endpoint"
    text = f"Threat payload located at {valid_url}"
    urls = extract_urls(text)
    assert len(urls) == 1
    assert "evil.com:8080" in urls[0]

