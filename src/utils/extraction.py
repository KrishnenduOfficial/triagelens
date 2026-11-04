"""Indicator extraction utilities for TriageLens."""

import ipaddress
import re
from typing import List
import urllib.parse

# Characters commonly used to obfuscate text (zero-width spaces and formatting marks)
ZERO_WIDTH_CHARS = re.compile(r"[\u200b\u200c\u200d\u200e\u200f\u2060\ufeff]")

# Common file extensions that must not be classified as domain TLDs
COMMON_NON_DOMAIN_EXTENSIONS = {
    "exe", "dll", "bin", "sys", "json", "csv", "txt", "log", "tmp", "bak",
    "py", "sh", "bat", "cmd", "ps1", "zip", "tar", "gz", "rar", "7z",
    "pdf", "docx", "xlsx", "pptx", "png", "jpg", "jpeg", "gif", "svg",
    "css", "js", "html", "htm", "xml", "yaml", "yml", "ini", "cfg", "conf",
    "so", "dylib", "apk", "jar", "war", "iso", "img", "vmdk", "dat",
}

# RFC 1918 Private IPv4 networks
RFC1918_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]


def is_public_ipv4(ip_str: str) -> bool:
    """Validates that a string is a valid, routable, non-private IPv4 address.

    Strictly rejects:
    - Out of range values (> 255)
    - RFC 1918 Private networks (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
    - Loopback (127.0.0.0/8)
    - Multicast (224.0.0.0/4)
    - Broadcast (255.255.255.255)
    - Unspecified (0.0.0.0)
    - Link-local APIPA (169.254.0.0/16)
    """
    try:
        ip = ipaddress.ip_address(ip_str)
        if not isinstance(ip, ipaddress.IPv4Address):
            return False

        # Strictly reject loopback, multicast, link-local, unspecified, and broadcast
        if (
            ip.is_loopback
            or ip.is_multicast
            or ip.is_link_local
            or ip.is_unspecified
            or ip == ipaddress.IPv4Address("255.255.255.255")
        ):
            return False

        # Strictly reject RFC 1918 private address ranges
        for net in RFC1918_NETWORKS:
            if ip in net:
                return False

        return True
    except ValueError:
        return False


def is_valid_domain(candidate: str) -> bool:
    """Validates if a candidate token is a syntactically valid domain name.

    Supports Punycode (xn--) and internationalized domain names.
    Rejects IP addresses, file names with non-domain extensions, and malformed labels.
    """
    cand = candidate.strip(".,;:?!'\"()[]{}<>`")
    if len(cand) < 4 or len(cand) > 253:
        return False
    if "://" in cand or "/" in cand or "@" in cand or ":" in cand:
        return False

    # Reject IPv4 / IPv6 addresses
    try:
        ipaddress.ip_address(cand)
        return False
    except ValueError:
        pass

    # IDN to Punycode validation
    try:
        ascii_cand = cand.encode("idna").decode("ascii")
    except (UnicodeError, UnicodeDecodeError, ValueError):
        return False

    parts = ascii_cand.split(".")
    if len(parts) < 2:
        return False

    tld = parts[-1].lower()
    if tld in COMMON_NON_DOMAIN_EXTENSIONS:
        return False

    # TLD must be punycode (xn--) or a 2-63 letter alphabetic string
    if not (tld.startswith("xn--") or (tld.isalpha() and 2 <= len(tld) <= 63)):
        return False

    # Validate each subdomain label
    for label in parts[:-1]:
        if not label or len(label) > 63:
            return False
        if not (label[0].isalnum() and label[-1].isalnum()):
            return False
        if not all(c.isalnum() or c == "-" for c in label):
            return False

    return True


def extract_ips(text: str) -> List[str]:
    """Extracts unique, routable public IPv4 addresses from text.

    Strictly rejects RFC 1918 private IPs, loopbacks (127.0.0.1), multicast,
    broadcast, and out-of-range octets. ReDoS safe.
    """
    if not text or not isinstance(text, str):
        return []

    cleaned = ZERO_WIDTH_CHARS.sub("", text)
    candidates = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", cleaned)

    seen = set()
    valid_ips: List[str] = []
    for cand in candidates:
        if is_public_ipv4(cand) and cand not in seen:
            seen.add(cand)
            valid_ips.append(cand)

    return valid_ips


def extract_domains(text: str) -> List[str]:
    """Extracts unique domain names from text.

    Supports Punycode (xn--) and internationalized domain names.
    Excludes file extensions, paths, and IP addresses. ReDoS safe.
    """
    if not text or not isinstance(text, str):
        return []

    cleaned = ZERO_WIDTH_CHARS.sub("", text)
    tokens = re.findall(r"[^\s<>\";,'`()\[\]{}]+", cleaned)

    seen = set()
    domains: List[str] = []
    for token in tokens:
        clean_token = token.strip(".,;:?!'\"()[]{}<>`")
        if is_valid_domain(clean_token):
            norm_token = clean_token.lower()
            if norm_token not in seen:
                seen.add(norm_token)
                domains.append(norm_token)

    return domains


def extract_hashes(text: str) -> List[str]:
    """Extracts MD5 (32 hex), SHA-1 (40 hex), and SHA-256 (64 hex) hashes from text.

    Removes zero-width obfuscation characters before scanning. ReDoS safe.
    """
    if not text or not isinstance(text, str):
        return []

    cleaned = ZERO_WIDTH_CHARS.sub("", text)

    seen = set()
    hashes: List[str] = []
    for match in re.finditer(r"\b[a-fA-F0-9]{32,64}\b", cleaned):
        h = match.group()
        length = len(h)
        if length in (32, 40, 64):
            val = h.lower()
            if val not in seen:
                seen.add(val)
                hashes.append(val)

    return hashes


def extract_urls(text: str) -> List[str]:
    """Extracts valid HTTP and HTTPS URLs from text.

    Validates URL scheme, hostname, and port numbers (1-65535).
    Rejects malformed URLs, excessive ports, and repeating-scheme ReDoS attacks.
    Supports credential injection.
    """
    if not text or not isinstance(text, str):
        return []

    cleaned = ZERO_WIDTH_CHARS.sub("", text)
    url_candidates = re.findall(r"https?://[^\s<>\"'`{}|\\^\[\]]+", cleaned)

    seen = set()
    urls: List[str] = []
    for cand in url_candidates:
        clean_cand = cand.rstrip(".,;:!?'\")")
        try:
            parsed = urllib.parse.urlsplit(clean_cand)
            if parsed.scheme not in ("http", "https"):
                continue

            hostname = parsed.hostname
            if not hostname:
                continue

            hostname_clean = hostname.strip().lower()
            if hostname_clean.startswith("http") or "://" in hostname_clean or "/" in hostname_clean:
                continue

            # Hostname must be a valid domain or public/valid IP or localhost
            if not (is_valid_domain(hostname_clean) or is_public_ipv4(hostname_clean) or hostname_clean == "localhost"):
                continue

            if parsed.port is not None:
                if not (1 <= parsed.port <= 65535):
                    continue

            if clean_cand not in seen:
                seen.add(clean_cand)
                urls.append(clean_cand)
        except ValueError:
            continue

    return urls
