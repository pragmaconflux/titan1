#!/usr/bin/env python3
"""Stress test harness for Titan Decoder Engine.

This is intentionally NOT a pytest test: it's a repeatable load/stress runner that
exercises decoding/analyzers/IOC extraction paths and reports timing + memory.

Usage examples:
  python scripts/stress_test_engine.py --iterations 50
  python scripts/stress_test_engine.py --iterations 200 --size 65536 --profile full
  python scripts/stress_test_engine.py --scenario all --json-out /tmp/stress.json
"""

from __future__ import annotations

import argparse
import base64
import bz2
import gzip
import json
import lzma
import os
import random
import sys
import statistics
import tarfile
import time
import tracemalloc
import zlib
from dataclasses import dataclass
from io import BytesIO
from pathlib import Path
from typing import Callable, Dict, List, Sequence

# Allow running directly without installing the package.
REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from titan_decoder.config import Config  # noqa: E402
from titan_decoder.core.engine import TitanEngine  # noqa: E402


@dataclass(frozen=True)
class RunResult:
    scenario: str
    ok: bool
    seconds: float
    peak_kib: float
    node_count: int
    ioc_total: int
    payload_name: str | None = None
    error: str | None = None


def _rand_bytes(rng: random.Random, size: int) -> bytes:
    return (
        rng.randbytes(size)
        if hasattr(rng, "randbytes")
        else bytes(rng.getrandbits(8) for _ in range(size))
    )


def _nested_base64(data: bytes, layers: int) -> bytes:
    out = data
    for _ in range(layers):
        out = base64.b64encode(out)
    return out


def _xor(data: bytes, key: int) -> bytes:
    key &= 0xFF
    return bytes((b ^ key) for b in data)


def _gzip(data: bytes) -> bytes:
    return gzip.compress(data)


def _bz2(data: bytes) -> bytes:
    return bz2.compress(data)


def _lzma(data: bytes) -> bytes:
    return lzma.compress(data)


def _zlib(data: bytes) -> bytes:
    return zlib.compress(data)


def _zip_many_files(rng: random.Random, file_count: int, file_size: int) -> bytes:
    import zipfile

    buf = BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for i in range(file_count):
            name = f"file_{i:04d}.bin"
            zf.writestr(name, _rand_bytes(rng, file_size))
    return buf.getvalue()


def _tar_many_files(rng: random.Random, file_count: int, file_size: int) -> bytes:
    buf = BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        for i in range(file_count):
            data = _rand_bytes(rng, file_size)
            info = tarfile.TarInfo(name=f"file_{i:04d}.bin")
            info.size = len(data)
            tf.addfile(info, BytesIO(data))
    return buf.getvalue()


def scenario_random_noise(rng: random.Random, size: int) -> bytes:
    return _rand_bytes(rng, size)


def scenario_deep_base64_with_iocs(rng: random.Random, size: int) -> bytes:
    # Put some IOCs in the plaintext so extraction has something to find.
    s = (
        "GET http://malicious.example/path?x=1\n"
        "contact: test@evil.example\n"
        "c2=1.2.3.4\n"
    ).encode("utf-8")
    padding = _rand_bytes(rng, max(0, size - len(s)))
    blob = s + padding
    return _nested_base64(blob, layers=5)


def scenario_mixed_compression_chain(rng: random.Random, size: int) -> bytes:
    data = _rand_bytes(rng, size)
    # Chain multiple codecs to build depth + variety.
    data = _gzip(data)
    data = _zlib(data)
    data = _bz2(data)
    return base64.b64encode(data)


def scenario_xor_obfuscated_text(rng: random.Random, size: int) -> bytes:
    text = (
        "powershell -enc AAAA\ncurl http://c2.example\nuser=admin@example.com\n"
    ).encode("utf-8")
    padding = _rand_bytes(rng, max(0, size - len(text)))
    blob = text + padding
    # XOR it so the XOR decoder / detection paths get exercised.
    return _xor(blob, key=0x42)


def scenario_zip_many_small(rng: random.Random, _: int) -> bytes:
    return _zip_many_files(rng, file_count=30, file_size=1024)


def scenario_tar_many_small(rng: random.Random, _: int) -> bytes:
    return _tar_many_files(rng, file_count=30, file_size=1024)


SCENARIOS: Dict[str, Callable[[random.Random, int], bytes]] = {
    "random": scenario_random_noise,
    "deep_base64": scenario_deep_base64_with_iocs,
    "mixed_chain": scenario_mixed_compression_chain,
    "xor_text": scenario_xor_obfuscated_text,
    "zip_many": scenario_zip_many_small,
    "tar_many": scenario_tar_many_small,
}


def build_config(profile: str) -> Config:
    cfg = Config()

    if profile == "fast":
        cfg.set("max_recursion_depth", 3)
        cfg.set("max_node_count", 50)
    elif profile == "full":
        cfg.set("max_recursion_depth", 8)
        cfg.set("max_node_count", 200)
    else:
        raise ValueError(f"Unknown profile: {profile}")

    # Keep stress predictable.
    cfg.set("enable_correlation", False)
    cfg.set("enable_logging", False)

    return cfg


def run_one(
    engine: TitanEngine,
    scenario: str,
    payload: bytes,
    *,
    payload_name: str | None = None,
) -> RunResult:
    tracemalloc.start()
    start = time.perf_counter()
    try:
        report = engine.run_analysis(payload)
        ok = True
        err = None
    except Exception as e:
        report = {"node_count": 0, "iocs": {}}
        ok = False
        err = f"{type(e).__name__}: {e}"
    seconds = time.perf_counter() - start
    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    iocs = report.get("iocs", {}) or {}
    ioc_total = 0
    try:
        ioc_total = sum(len(v) for v in iocs.values() if isinstance(v, list))
    except Exception:
        ioc_total = 0

    return RunResult(
        scenario=scenario,
        ok=ok,
        seconds=seconds,
        peak_kib=peak / 1024.0,
        node_count=int(report.get("node_count", 0) or 0),
        ioc_total=ioc_total,
        payload_name=payload_name,
        error=err,
    )


def _iter_payload_files(
    *,
    payload_paths: Sequence[str],
    payload_dirs: Sequence[str],
    glob_pattern: str,
) -> List[Path]:
    files: List[Path] = []

    for p in payload_paths:
        path = Path(p)
        if path.is_file():
            files.append(path)

    for d in payload_dirs:
        root = Path(d)
        if not root.is_dir():
            continue
        files.extend([p for p in root.glob(glob_pattern) if p.is_file()])

    # Deterministic ordering for stable runs.
    return sorted(set(files))


def _load_payload(path: Path, *, max_bytes: int) -> bytes:
    with path.open("rb") as f:
        return f.read(max_bytes)


def summarize(results: List[RunResult]) -> Dict[str, Dict[str, float]]:
    by_s: Dict[str, List[RunResult]] = {}
    for r in results:
        by_s.setdefault(r.scenario, []).append(r)

    summary: Dict[str, Dict[str, float]] = {}
    for name, rows in by_s.items():
        secs = [r.seconds for r in rows]
        peaks = [r.peak_kib for r in rows]
        nodes = [r.node_count for r in rows]
        ok_rate = sum(1 for r in rows if r.ok) / max(1, len(rows))
        summary[name] = {
            "runs": float(len(rows)),
            "ok_rate": ok_rate,
            "p50_s": statistics.median(secs),
            "p95_s": sorted(secs)[int(0.95 * (len(secs) - 1))]
            if len(secs) > 1
            else secs[0],
            "p50_peak_kib": statistics.median(peaks),
            "p95_peak_kib": sorted(peaks)[int(0.95 * (len(peaks) - 1))]
            if len(peaks) > 1
            else peaks[0],
            "p50_nodes": statistics.median(nodes),
            "p95_nodes": sorted(nodes)[int(0.95 * (len(nodes) - 1))]
            if len(nodes) > 1
            else nodes[0],
        }

    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description="Titan Engine stress runner")
    parser.add_argument("--iterations", type=int, default=50, help="Runs per scenario")
    parser.add_argument(
        "--scenario",
        choices=["all", *sorted(SCENARIOS.keys())],
        default="all",
        help="Scenario to run",
    )
    parser.add_argument(
        "--payload",
        action="append",
        default=[],
        help="Path to a payload file to analyze (repeatable)",
    )
    parser.add_argument(
        "--payload-dir",
        action="append",
        default=[],
        help="Directory containing payload files to analyze (repeatable)",
    )
    parser.add_argument(
        "--payload-glob",
        type=str,
        default="**/*",
        help="Glob used under --payload-dir (default: **/*)",
    )
    parser.add_argument(
        "--payload-max-bytes",
        type=int,
        default=5 * 1024 * 1024,
        help="Max bytes to read per payload file (default: 5 MiB)",
    )
    parser.add_argument(
        "--payload-limit",
        type=int,
        default=0,
        help="Max number of payload files to load (0 = no limit)",
    )
    parser.add_argument(
        "--payload-sample",
        type=int,
        default=0,
        help="Randomly sample N payload files (0 = no sampling)",
    )
    parser.add_argument(
        "--payload-repeat",
        type=int,
        default=1,
        help="Repeat the full payload corpus N times (default: 1)",
    )
    parser.add_argument(
        "--size",
        type=int,
        default=32 * 1024,
        help="Payload size for byte-oriented scenarios",
    )
    parser.add_argument("--profile", choices=["fast", "full"], default="fast")
    parser.add_argument("--seed", type=int, default=1337)
    parser.add_argument(
        "--json-out", type=str, default="", help="Write detailed results to JSON file"
    )

    args = parser.parse_args()

    rng = random.Random(args.seed)
    cfg = build_config(args.profile)
    engine = TitanEngine(cfg)

    scenario_names = (
        sorted(SCENARIOS.keys()) if args.scenario == "all" else [args.scenario]
    )

    payload_files = _iter_payload_files(
        payload_paths=args.payload,
        payload_dirs=args.payload_dir,
        glob_pattern=args.payload_glob,
    )
    if args.payload_limit and args.payload_limit > 0:
        payload_files = payload_files[: args.payload_limit]
    if args.payload_sample and args.payload_sample > 0 and payload_files:
        sample_n = min(args.payload_sample, len(payload_files))
        payload_files = rng.sample(payload_files, sample_n)

    results: List[RunResult] = []
    started = time.perf_counter()
    for name in scenario_names:
        gen = SCENARIOS[name]
        for _ in range(args.iterations):
            payload = gen(rng, args.size)
            results.append(run_one(engine, name, payload))

    if payload_files:
        for _ in range(max(1, args.payload_repeat)):
            for path in payload_files:
                data = _load_payload(path, max_bytes=args.payload_max_bytes)
                results.append(run_one(engine, "corpus", data, payload_name=str(path)))

    total_s = time.perf_counter() - started

    # Print a compact summary.
    print("\nTitan stress summary")
    print(
        f"profile={args.profile} iterations={args.iterations} size={args.size} seed={args.seed}"
    )
    if payload_files:
        print(
            f"payload_files={len(payload_files)} payload_repeat={args.payload_repeat} "
            f"payload_max_bytes={args.payload_max_bytes}"
        )
    print(f"total_seconds={total_s:.3f}")
    print(
        "\nscenario\truns\tok_rate\tp50_s\tp95_s\tp50_peak_kib\tp95_peak_kib\tp50_nodes\tp95_nodes"
    )
    summary = summarize(results)
    for name in [*scenario_names, *(["corpus"] if payload_files else [])]:
        s = summary[name]
        print(
            f"{name}\t{int(s['runs'])}\t{s['ok_rate']:.2f}\t{s['p50_s']:.4f}\t{s['p95_s']:.4f}"
            f"\t{s['p50_peak_kib']:.1f}\t{s['p95_peak_kib']:.1f}"
            f"\t{int(s['p50_nodes'])}\t{int(s['p95_nodes'])}"
        )

    # If there were failures, print the first few.
    failures = [r for r in results if not r.ok]
    if failures:
        print("\nFailures (first 5):")
        for r in failures[:5]:
            print(f"- {r.scenario}: {r.error}")

    if args.json_out:
        out = {
            "meta": {
                "cwd": os.getcwd(),
                "profile": args.profile,
                "iterations": args.iterations,
                "size": args.size,
                "seed": args.seed,
                "payload": {
                    "files": [str(p) for p in payload_files],
                    "repeat": args.payload_repeat,
                    "max_bytes": args.payload_max_bytes,
                },
            },
            "results": [r.__dict__ for r in results],
            "summary": summary,
        }
        with open(args.json_out, "w", encoding="utf-8") as f:
            json.dump(out, f, indent=2)
        print(f"\nWrote JSON results to {args.json_out}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
