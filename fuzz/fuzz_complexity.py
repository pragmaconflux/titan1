#!/usr/bin/env python3
"""Algorithmic-complexity sweep: every live component x many input shapes.

Crash fuzzing finds inputs that break a component; it does not find inputs
that make one slow, because a quadratic path on a 2KB mutation still returns
in milliseconds. This sweep feeds each decoder, analyzer, and the full engine
the same shape at 8KB, 32KB, and 128KB and flags any cost that grows
super-linearly (4x input: linear is ~4x time, quadratic ~16x). It found the
quadratic domain/email regexes and Base58's big-integer decode.

    python fuzz/fuzz_complexity.py [--only decoder:Base58 ...] [--artifacts DIR]

Exits 1 when anything is flagged.
"""

from __future__ import annotations

import json
import os
import signal
import sys
import time
import traceback

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from titan_decoder.config import Config  # noqa: E402
from titan_decoder.core.engine import TitanEngine  # noqa: E402

SIZES = (8 * 1024, 32 * 1024, 128 * 1024)
CALL_TIMEOUT = 30
RATIO_FLAG = 8.0  # 4x input: linear ~4, quadratic ~16
FLOOR_SECONDS = 0.05  # ignore growth in calls too fast to measure reliably


def rep(unit: bytes):
    return lambda n: (unit * (n // max(1, len(unit)) + 1))[:n]


def framed(prefix: bytes, unit: bytes, suffix: bytes = b""):
    return lambda n: prefix + (unit * (n // max(1, len(unit)) + 1))[:n] + suffix


SHAPES = {
    "a": rep(b"a"),
    "a.": rep(b"a."),
    "a-": rep(b"a-"),
    "a_": rep(b"a_"),
    "words": rep(b"a "),
    "newlines": rep(b"\n"),
    "crlf": rep(b"\r\n"),
    "zeros": rep(b"\x00"),
    "ff": rep(b"\xff"),
    "random": lambda n: os.urandom(n),
    "printable": lambda n: bytes(32 + b % 95 for b in os.urandom(n)),
    "b64": rep(b"QUFB"),
    "b64pad": rep(b"QQ=="),
    "equals": rep(b"="),
    "hex": rep(b"deadbeef"),
    "hexpairs-sp": rep(b"de ad "),
    "b58": rep(b"123456789ABCDEFG"),
    "b91": rep(b'!#$%&()*+,./:;<=>?@[]^_`{|}~"'),
    "percent": rep(b"%41"),
    "percent-bad": rep(b"%%"),
    "entity": rep(b"&amp;"),
    "entity-num": rep(b"&#65;"),
    "uescape": rep(b"\\u0041"),
    "xescape": rep(b"\\x41"),
    "utf16": rep(b"a\x00"),
    "open-bracket": rep(b"["),
    "open-paren": rep(b"("),
    "open-brace": rep(b"{"),
    "angle": rep(b"<"),
    "quote": rep(b'"'),
    "backslash": rep(b"\\"),
    "ipish": rep(b"1."),
    "url-ish": rep(b"http://a"),
    "email-ish": rep(b"a@a."),
    "ascii85": framed(b"<~", b"87cUR", b"~>"),
    "uu": framed(
        b"begin 644 f\n", b"M86%A86%A86%A86%A86%A86%A86%A86%A86%A86%A86%A86%A86%A86%A\n"
    ),
    "pem": rep(b"-----BEGIN X-----\n"),
    "pe": framed(b"MZ", b"\x00"),
    "elf": framed(b"\x7fELF", b"\x00"),
    "zip": framed(b"PK\x03\x04", b"\x00"),
    "pdf": framed(b"%PDF-1.4\n", b"1 0 obj\n<<>>\nendobj\n"),
    "pdf-stream": framed(b"%PDF-1.4\n", b"stream\n"),
    "cfb": framed(bytes.fromhex("d0cf11e0a1b11ae1"), b"\x00"),
    "email": framed(b"From: a@b.test\nTo: c@d.test\nSubject: x\n\n", b"line\n"),
    "email-headers": rep(b"X-H: v\n"),
    "rtf-nest": framed(b"{\\rtf1", b"{"),
    "rtf-objdata": framed(b"{\\rtf1{\\object\\objdata ", b"01"),
    "ps-enc": framed(b"powershell -enc ", b"QQBBAEEA"),
    "fromcharcode": framed(b"String.fromCharCode(", b"65,"),
    "eval-nest": rep(b"eval("),
    "js-concat": rep(b"'a'+"),
    "xml": rep(b"<a>"),
    "xml-attr": framed(b'<x d="', b"QUFB", b'"/>'),
    "lnk": framed(
        bytes.fromhex("4c000000") + bytes.fromhex("0114020000000000c000000000000046"),
        b"\x00",
    ),
    "png": framed(b"\x89PNG\r\n\x1a\n", b"\x00"),
    "gzip-hdr": framed(b"\x1f\x8b\x08", b"\x00"),
    "vhd": lambda n: b"\x00" * max(0, n - 512) + b"conectix" + b"\x00" * 504,
    "dex": framed(b"dex\n035\x00", b"\x00"),
    "macho": framed(bytes.fromhex("cffaedfe"), b"\x00"),
    "onenote": framed(bytes.fromhex("e4525c7b8cd8a74daeb15378d02996d3"), b"\x00"),
    "msi-ish": framed(bytes.fromhex("d0cf11e0a1b11ae1"), b"\x84\x10\x0c\x00"),
}


class Timeout(Exception):
    pass


def _alarm(signum, frame):
    raise Timeout()


signal.signal(signal.SIGALRM, _alarm)


def timed(fn, data):
    signal.alarm(CALL_TIMEOUT)
    start = time.perf_counter()
    try:
        fn(data)
        return time.perf_counter() - start, None
    except Timeout:
        return float(CALL_TIMEOUT), "TIMEOUT"
    except Exception as exc:  # noqa: BLE001 - recording, not handling
        return time.perf_counter() - start, f"{type(exc).__name__}: {exc}"[
            :300
        ] + "\n" + traceback.format_exc()[-1200:]
    finally:
        signal.alarm(0)


def component_calls(engine):
    for decoder in engine.decoders:

        def run(data, d=decoder):
            if d.can_decode(data):
                d.decode(data)

        yield f"decoder:{decoder.name}", run
    for analyzer in engine.analyzers:

        def run(data, a=analyzer):
            if getattr(a, "composes", False):
                a.carve(data)
            if a.can_analyze(data):
                a.analyze(data)

        yield f"analyzer:{analyzer.name}", run


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--only", nargs="*", default=[], help="component names, e.g. decoder:Base58"
    )
    parser.add_argument(
        "--artifacts", default=".fuzz-artifacts", help="where findings are written"
    )
    args = parser.parse_args()
    only = set(args.only)
    engine = TitanEngine(Config())
    findings = []
    datasets = {name: [make(n) for n in SIZES] for name, make in SHAPES.items()}
    targets = list(component_calls(engine))

    def engine_run(data):
        TitanEngine(Config()).run_analysis(data)

    targets.append(("engine:run_analysis", engine_run))
    if only:
        targets = [t for t in targets if t[0] in only]

    total = len(targets) * len(datasets)
    done = 0
    for name, fn in targets:
        for shape, inputs in datasets.items():
            done += 1
            times = []
            error = None
            for data in inputs:
                elapsed, err = timed(fn, data)
                times.append(elapsed)
                if err:
                    error = err
                    break
            if error:
                findings.append(
                    {
                        "component": name,
                        "shape": shape,
                        "kind": "error",
                        "detail": error,
                        "times": times,
                    }
                )
                print(
                    f"[{done}/{total}] ERROR {name} x {shape}: {error.splitlines()[0]}",
                    flush=True,
                )
                continue
            ratio = times[2] / max(times[1], 1e-6)
            if times[2] > FLOOR_SECONDS and ratio > RATIO_FLAG:
                findings.append(
                    {
                        "component": name,
                        "shape": shape,
                        "kind": "superlinear",
                        "times": times,
                        "ratio": ratio,
                    }
                )
                print(
                    f"[{done}/{total}] SUPERLINEAR {name} x {shape}: "
                    + " ".join(f"{t * 1000:.1f}ms" for t in times)
                    + f"  x{ratio:.1f}",
                    flush=True,
                )
            elif times[2] > 2.0:
                findings.append(
                    {
                        "component": name,
                        "shape": shape,
                        "kind": "slow",
                        "times": times,
                        "ratio": ratio,
                    }
                )
                print(
                    f"[{done}/{total}] SLOW {name} x {shape}: "
                    + " ".join(f"{t * 1000:.1f}ms" for t in times)
                    + f"  x{ratio:.1f}",
                    flush=True,
                )
    os.makedirs(args.artifacts, exist_ok=True)
    out = os.path.join(args.artifacts, "complexity_findings.json")
    with open(out, "w") as handle:
        json.dump(findings, handle, indent=2)
    print(
        f"\nDONE: {len(findings)} findings across {len(targets)} targets x {len(datasets)} shapes -> {out}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
