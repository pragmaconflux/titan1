"""Decoder selection must not prefer garbage over a clean decode.

Decoding is winner-takes-all: the highest-scoring decoder becomes the node's
interpretation and the others are discarded, so a wrong pick means the real
payload is never produced at all.

Entropy reduction and printable *gain* both measure improvement, which leaves
them blind when the input is already fully printable -- both score zero and
decoder cost alone decides. An even-length hex string is also valid base64, so
both decoders accept it, and Base64 (cost 1) outranked Hex (cost 2): the engine
returned high-entropy noise where Hex returned clean ASCII.
"""

import base64
import zlib

from titan_decoder.config import Config
from titan_decoder.core.engine import TitanEngine
from titan_decoder.core.scoring import ScoringEngine
from titan_decoder.decoders.base import Base64Decoder, HexDecoder

HEX_PAYLOAD = b"4865782063616c6962726174696f6e207061796c6f616421"


def _engine():
    config = Config()
    config.set("max_recursion_depth", 8)
    return TitanEngine(config)


def test_both_decoders_accept_an_even_length_hex_string():
    # The premise of the conflict: this is not a can_decode bug, both are
    # legitimately willing to decode it.
    assert HexDecoder().can_decode(HEX_PAYLOAD)
    assert Base64Decoder().can_decode(HEX_PAYLOAD)


def test_clean_decode_outscores_noise_on_identical_input():
    scoring = ScoringEngine()
    hex_score = scoring.calculate_decode_score(
        HEX_PAYLOAD, HexDecoder().decode(HEX_PAYLOAD)[0], "Hex", 0
    )
    base64_score = scoring.calculate_decode_score(
        HEX_PAYLOAD, Base64Decoder().decode(HEX_PAYLOAD)[0], "Base64", 0
    )
    assert hex_score > base64_score


def test_engine_produces_the_readable_interpretation():
    report = _engine().run_analysis(HEX_PAYLOAD)
    assert report["nodes"][0]["method"] == "DECODE_Hex"
    assert any(
        "Hex calibration payload!" in node["content_preview"]
        for node in report["nodes"]
    )


def test_recognizable_binary_output_is_not_penalized():
    # base64-wrapped executables and archives must keep their scores; the
    # penalty is for destroying structure and producing nothing recognizable.
    scoring = ScoringEngine()
    for payload in (
        b"MZ\x90\x00" + b"\x00" * 128,
        b"PK\x03\x04" + b"\x00" * 128,
        zlib.compress(b"body " * 64),
    ):
        wrapped = base64.b64encode(payload)
        assert scoring._output_plausibility(wrapped, payload) == 1.0


def test_binary_input_is_not_penalized():
    # The penalty only applies when readable input becomes unreadable output.
    scoring = ScoringEngine()
    compressed = zlib.compress(b"log line " * 64)
    assert scoring._output_plausibility(compressed, b"\x00\x01\x02\x03" * 32) == 1.0


def test_printable_output_is_not_penalized():
    scoring = ScoringEngine()
    assert (
        scoring._output_plausibility(b"aaaa bbbb cccc", b"plain readable text") == 1.0
    )


def test_unrecognizable_output_from_clean_text_is_demoted_not_dropped():
    scoring = ScoringEngine()
    noise = bytes((index * 173 + 7) % 256 for index in range(96))
    retention = scoring._output_plausibility(b"readable input text here", noise)
    assert retention == ScoringEngine.IMPLAUSIBLE_OUTPUT_RETENTION
    assert 0 < retention < 1, "demote competing interpretations, never zero them"


def test_penalized_decode_still_appears_when_nothing_competes():
    # A lone spurious decode keeps its node, with an honest lower confidence,
    # rather than vanishing from the graph.
    report = _engine().run_analysis(base64.b64encode(b"INFO log line ok\n" * 8))
    assert len(report["nodes"]) >= 2
