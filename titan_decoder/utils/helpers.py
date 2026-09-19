import hashlib
import ipaddress
import math
from typing import Dict, List
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
    freq: Dict[int, int] = {}
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


# Container/executable signatures that mark decoded output as a real payload
# even when it is not printable. Shared by the transport decoders and the
# embedded-payload carver so both judge "did this decode to something" the
# same way.
PAYLOAD_MAGICS = (
    b"MZ",
    b"\x7fELF",
    b"PK\x03\x04",
    b"%PDF-",
    b"\x1f\x8b\x08",
    b"BZh",
    b"\xfd7zXZ\x00",
    b"Rar!\x1a\x07",
    b"#!/",
)


def looks_meaningful_payload(data: bytes) -> bool:
    """Return whether decoded bytes look like a real payload rather than noise.

    Either the output carries a known container/executable signature, or it is
    overwhelmingly printable. Random bytes that happen to survive a decode fail
    both checks, which is what keeps speculative decoding from manufacturing
    artifacts.
    """
    if len(data) < 4:
        return False
    if any(data.startswith(magic) for magic in PAYLOAD_MAGICS):
        return True
    sample = data[:8192]
    printable = sum(value in (9, 10, 13) or 32 <= value < 127 for value in sample)
    return printable / len(sample) >= 0.88


def looks_like_base64(data: bytes) -> bool:
    """Check if data looks like base64 encoded."""
    try:
        text = data.decode("ascii").strip()
    except UnicodeDecodeError:
        return False

    # Ignore whitespace/newlines for validation.
    text = re.sub(r"\s+", "", text)
    if len(text) < 16:
        return False
    if not re.fullmatch(r"[A-Za-z0-9+/=]+", text):
        return False
    try:
        import base64

        base64.b64decode(text, validate=True)
        return True
    except Exception:
        return False


def looks_like_zip(data: bytes) -> bool:
    """Check if data looks like a ZIP file."""
    return (
        data.startswith(b"PK\x03\x04")
        or data.startswith(b"PK\x05\x06")
        or data.startswith(b"PK\x07\x08")
    )


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
    except UnicodeDecodeError:
        return False
    if not text or len(text) % 2 != 0:
        return False
    # Strict hex-digit check. ``int(text, 16)`` also accepts forms unhexlify
    # rejects ("0x" prefixes, +/- signs, "_" separators), so the decoder was
    # offered data it could never decode.
    return bool(re.fullmatch(r"[0-9a-fA-F]+", text))


# =========================
# IOC Extraction
# =========================

# Common file extensions that the domain regex would otherwise mistake for a
# TLD (e.g. "config.json", "gate.php", "payload.txt" -> bogus domains). Every
# entry here is NOT a real TLD, so filtering on them never drops a real domain.
# Ambiguous extensions that *are* ccTLDs/gTLDs (sh, py, io, zip, mov, md, ...)
# are deliberately omitted to avoid false negatives.
COMMON_FILE_EXTENSIONS = frozenset(
    {
        "txt",
        "log",
        "json",
        "xml",
        "csv",
        "yaml",
        "yml",
        "toml",
        "ini",
        "cfg",
        "conf",
        "php",
        "html",
        "htm",
        "css",
        "js",
        "jsx",
        "ts",
        "tsx",
        "exe",
        "dll",
        "bin",
        "dat",
        "dmp",
        "img",
        "iso",
        "msi",
        "apk",
        "ipa",
        "deb",
        "rpm",
        "png",
        "jpg",
        "jpeg",
        "gif",
        "bmp",
        "svg",
        "ico",
        "webp",
        "pdf",
        "doc",
        "docx",
        "xls",
        "xlsx",
        "ppt",
        "pptx",
        "odt",
        "rtf",
        "bak",
        "tmp",
        "swp",
        "lock",
        "sqlite",
        "db",
        "ps1",
        "psm1",
        "vbs",
        "asp",
        "aspx",
        "jsp",
        "jar",
        "war",
        "ear",
        "class",
        "pyc",
        "pyo",
        "woff",
        "woff2",
        "ttf",
        "otf",
        "eot",
        "mp3",
        "mp4",
        "avi",
        "mkv",
        "wav",
        "flac",
        "webm",
        "gz",
        "bz2",
        "xz",
        "tgz",
        "vhd",
        "vmdk",
        "pem",
        "crt",
        "der",
        "pfx",
        "manifest",
    }
)

# Code/API member identifiers whose final label the domain regex would otherwise
# mistake for a TLD. Download-cradle payloads are full of dotted .NET/scripting
# member access (e.g. "Net.WebClient", "Net.HttpWebRequest") that looks like a
# two-label domain but whose trailing label is not a real TLD. Every entry here
# is verified NOT to exist in the IANA root zone, so filtering on them never
# drops a real domain (matching the false-negative-averse policy above).
NON_TLD_CODE_IDENTIFIERS = frozenset(
    {
        "webclient",
        "webrequest",
        "httpwebrequest",
        "httpclient",
        "downloadstring",
        "downloaddata",
        "downloadfile",
        "webproxy",
        "tcpclient",
        "socket",
        "sockets",
        "streamreader",
        "streamwriter",
        "memorystream",
        "filestream",
        "bitconverter",
        "encoding",
        "convert",
        "invoke",
        "createinstance",
    }
)


def is_private_ip(ip: str) -> bool:
    """Return True if ip is a valid IPv4 address that is not globally routable.

    Covers the RFC1918 private ranges plus loopback, link-local, CGNAT, and
    other reserved/special-use space — anything that should not be treated as a
    public indicator. Returns False for invalid addresses.
    """
    try:
        return not ipaddress.IPv4Address(ip).is_global
    except ValueError:
        return False


def _clean_indicator(val: str) -> str:
    """Basic IOC hygiene: strip surrounding punctuation and whitespace."""
    if not val:
        return ""
    return val.strip().strip("[](){}<>.,;'\"\n\r")


def extract_iocs(text: str) -> Dict[str, List[str]]:
    """Extract indicators of compromise from text with light normalization."""
    iocs: Dict[str, set] = {
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

    # Percent-encoded artifacts can cause noisy matches (e.g., '%2F%2Fcdn.example'
    # turning into a false domain '2fcdn.example'). Build two extra views:
    # - percent_stripped: removes %XX sequences to avoid spurious boundaries
    # - percent_decoded: recovers real URLs/emails that may be encoded
    try:
        import urllib.parse

        percent_decoded = urllib.parse.unquote(text)
    except Exception:
        percent_decoded = text

    percent_stripped = re.sub(r"%[0-9A-Fa-f]{2}", " ", text)

    text_for_urls = text + "\n" + percent_decoded
    text_for_other = percent_stripped + "\n" + percent_decoded

    ipv4 = re.findall(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", text_for_other)
    urls = re.findall(r"\bhttps?://[^\s\"']+\b", text_for_urls)
    domains = re.findall(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b", text_for_other)
    emails = re.findall(
        # TLD class was [A-Z|a-z], which includes a literal '|' inside the
        # character class (a common regex mistake) and matched bogus TLDs like
        # ".co|m"; the intent is just letters.
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
        text_for_other,
    )
    # Match only real hash digest lengths (hex): MD5=32, SHA1=40, SHA224=56,
    # SHA256=64, SHA384=96, SHA512=128. A loose {32,128} range would flag any
    # hex-encoded blob (e.g. a 34-char hex payload) as a bogus "hash" IOC.
    hashes = re.findall(
        r"\b(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{56}"
        r"|[a-fA-F0-9]{64}|[a-fA-F0-9]{96}|[a-fA-F0-9]{128})\b",
        text_for_other,
    )

    for raw_ip in ipv4:
        ip = _clean_indicator(raw_ip)
        if not ip:
            continue
        try:
            # Reject malformed addresses (e.g. octets > 255 like 999.999.999.999).
            ipaddress.IPv4Address(ip)
        except ValueError:
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
        if not domain:
            continue
        # Drop filename-like matches (e.g. config.json) whose final label is a
        # known non-TLD file extension, and code member access (e.g.
        # Net.WebClient) whose final label is a known non-TLD identifier.
        final_label = domain.rsplit(".", 1)[-1]
        if final_label in COMMON_FILE_EXTENSIONS:
            continue
        if final_label in NON_TLD_CODE_IDENTIFIERS:
            continue
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
