import hashlib
import math
from typing import Dict, Any, List, Set
import re

# =========================
# Utility Functions
# =========================

def sha256(data: bytes) -> str:
    """Calculate SHA256 hash of data."""
    return hashlib.sha256(data).hexdigest()


def entropy(data: bytes) -> float:
    """Calculate Shannon entropy of data."""
    if not data:
        return 0.0
    freq = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    ent = 0.0
    for count in freq.values():
        p = count / len(data)
        ent -= p * math.log2(p)
    return round(ent, 4)


def looks_like_text(data: bytes) -> bool:
    """Check if data looks like UTF-8 text."""
    try:
        data.decode("utf-8")
        return True
    except UnicodeDecodeError:
        return False


def looks_like_base64(data: bytes) -> bool:
    """Check if data looks like base64 encoded."""
    try:
        text = data.decode("ascii").strip()
    except UnicodeDecodeError:
        return False
    if len(text) < 16:
        return False
    if not re.fullmatch(r"[A-Za-z0-9+/=\s]+", text):
        return False
    try:
        import base64
        base64.b64decode(text, validate=True)
        return True
    except Exception:
        return False


def looks_like_zip(data: bytes) -> bool:
    """Check if data looks like a ZIP file."""
    return data.startswith(b"PK\x03\x04") or data.startswith(b"PK\x05\x06") or data.startswith(b"PK\x07\x08")


def looks_like_gzip(data: bytes) -> bool:
    """Check if data looks like gzip compressed."""
    return data.startswith(b"\x1f\x8b")


def looks_like_bz2(data: bytes) -> bool:
    """Check if data looks like bz2 compressed."""
    return data.startswith(b"BZ")


def looks_like_hex(data: bytes) -> bool:
    """Check if data looks like hex encoded."""
    try:
        text = data.decode("ascii").strip()
        if len(text) % 2 != 0:
            return False
        int(text, 16)
        return True
    except:
        return False


# =========================
# IOC Extraction
# =========================

PRIVATE_IP_RANGES = [
    re.compile(r"^10\."),
    re.compile(r"^192\.168\."),
    re.compile(r"^172\.(1[6-9]|2[0-9]|3[0-1])\."),
]

def is_private_ip(ip: str) -> bool:
    """Check if IP is private."""
    return any(r.match(ip) for r in PRIVATE_IP_RANGES)


def _clean_indicator(val: str) -> str:
    """Basic IOC hygiene: strip surrounding punctuation and whitespace."""
    if not val:
        return ""
    return val.strip().strip("[](){}<>.,;'\"\n\r")


def extract_iocs(text: str) -> Dict[str, List[str]]:
    """Extract indicators of compromise from text with light normalization."""
    iocs = {
        "ipv4": set(),
        "ipv4_public": set(),
        "ipv4_private": set(),
        "urls": set(),
        "domains": set(),
        "emails": set(),
        "hashes": set(),
    }

    if not text:
        return {k: [] for k in iocs}

    ipv4 = re.findall(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", text)
    urls = re.findall(r"\bhttps?://[^\s\"']+\b", text)
    domains = re.findall(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b", text)
    emails = re.findall(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", text)
    hashes = re.findall(r"\b[a-fA-F0-9]{32,128}\b", text)  # MD5, SHA1, SHA256, etc.

    for raw_ip in ipv4:
        ip = _clean_indicator(raw_ip)
        if not ip:
            continue
        iocs["ipv4"].add(ip)
        if is_private_ip(ip):
            iocs["ipv4_private"].add(ip)
        else:
            iocs["ipv4_public"].add(ip)

    for raw_url in urls:
        url = _clean_indicator(raw_url)
        if url:
            iocs["urls"].add(url)

    for raw_domain in domains:
        domain = _clean_indicator(raw_domain).lower()
        if domain:
            iocs["domains"].add(domain)

    for raw_email in emails:
        email = _clean_indicator(raw_email).lower()
        if email:
            iocs["emails"].add(email)

    for raw_hash in hashes:
        h = _clean_indicator(raw_hash).lower()
        if h:
            iocs["hashes"].add(h)

    return {k: sorted(v) for k, v in iocs.items()}