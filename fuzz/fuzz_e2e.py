#!/usr/bin/env python3
"""End-to-end mutation campaign: the real CLI with every report output on.

fuzz_decoders.py checks components in isolation; this drives mutated inputs
through cli.main() in-process -- engine, detections, intelligence, every
export format, and the analyst -- and checks what a user would rely on:
exit status, report schema, graph and provenance integrity, IOC shape,
parseable exports, determinism across reruns, and that the analyst's own
deterministic answers pass its citation validator.

Seeds: every calibration case, the golden corpus, and fuzz/corpus. Mutators
include bit flips, truncation, duplication, base64/gzip/hex nesting, ZIP
wrapping with traversal names, and script hosting.

    python fuzz/fuzz_e2e.py --seconds 600 --seed 7 --artifacts .fuzz-artifacts

Exits 1 when any finding is recorded; each finding keeps its input.
"""

from __future__ import annotations

import base64
import contextlib
import csv
import gzip
import hashlib
import io
import json
import os
import random
import signal
import sys
import tempfile
import time
import traceback
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tools"))

import logging  # noqa: E402

logging.disable(logging.CRITICAL)

import jsonschema  # noqa: E402

from titan_decoder import cli  # noqa: E402
from titan_decoder.analyst.engine import AnalystEngine  # noqa: E402
from titan_decoder.analyst.validation import validate_answer  # noqa: E402
from titan_decoder.core.calibration import CalibrationRunner  # noqa: E402

SCHEMA = json.loads((ROOT / "docs" / "report.schema.json").read_text())
VOLATILE_META = {"analysis_id", "started_at", "finished_at", "duration_ms"}
QUESTIONS = (
    "What is this file?",
    "What indicators were found?",
    "Which detections fired and why?",
    "What ATT&CK techniques apply?",
    "What is the risk?",
    "Summarize the decoding chain.",
)
PER_INPUT_TIMEOUT = 120


class Timeout(Exception):
    pass


def _alarm(signum, frame):
    raise Timeout()


signal.signal(signal.SIGALRM, _alarm)


# --------------------------------------------------------------------- seeds
def load_seeds() -> list[tuple[str, bytes]]:
    seeds: list[tuple[str, bytes]] = []
    corpus_path = (
        ROOT / "tests" / "fixtures" / "calibration" / "decoder-analyzer-v1.json"
    )
    corpus = json.loads(corpus_path.read_text())
    defs = {c["id"]: c for c in corpus["cases"]}
    for case in corpus["cases"]:
        try:
            seeds.append(
                (
                    f"cal:{case['id']}",
                    CalibrationRunner._case_data(
                        case, corpus_path.parent, case_definitions=defs
                    ),
                )
            )
        except Exception:
            pass
    try:
        import golden  # type: ignore

        for name, data in golden.build_inputs().items():
            seeds.append((f"golden:{name}", data))
    except Exception:
        pass
    for path in sorted((ROOT / "fuzz" / "corpus").glob("*")):
        if path.is_file():
            seeds.append((f"corpus:{path.name}", path.read_bytes()))
    return [(n, d) for n, d in seeds if d]


# ------------------------------------------------------------------ mutators
def m_flip(r, d):
    b = bytearray(d)
    for _ in range(r.randint(1, max(1, len(b) // 64 + 1))):
        i = r.randrange(len(b))
        b[i] ^= 1 << r.randrange(8)
    return bytes(b)


def m_byte(r, d):
    b = bytearray(d)
    for _ in range(r.randint(1, 8)):
        b[r.randrange(len(b))] = r.choice(
            [0, 0xFF, 0x7F, 0x80, ord("."), ord("%"), ord("="), ord("\\")]
        )
    return bytes(b)


def m_insert(r, d):
    i = r.randrange(len(d) + 1)
    blob = r.choice(
        [
            os.urandom(r.randint(1, 64)),
            b"\x00" * r.randint(1, 512),
            b"A" * r.randint(1, 512),
            b"{" * r.randint(1, 300),
            b"%" * 50,
            b"\\u0041" * 40,
            b"<~" + b"z" * 100,
        ]
    )
    return d[:i] + blob + d[i:]


def m_delete(r, d):
    i = r.randrange(len(d))
    return d[:i] + d[i + r.randint(1, max(1, len(d) // 4)) :]


def m_dup(r, d):
    i = r.randrange(len(d))
    j = min(len(d), i + r.randint(1, 256))
    return d[:j] + d[i:j] * r.randint(2, 40) + d[j:]


def m_truncate(r, d):
    return d[: r.randrange(1, len(d) + 1)]


def m_b64(r, d):
    return base64.b64encode(d)


def m_gzip(r, d):
    return gzip.compress(d, mtime=0)


def m_zip(r, d):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr(
            r.choice(
                ["a.bin", "../../etc/passwd", "dir/x.js", "C:\\win.exe", "a" * 300]
            ),
            d,
        )
    return buf.getvalue()


def m_host(r, d):
    return b"var x = '" + base64.b64encode(d) + b"';\nrun(x);\n"


def m_nested(r, d):
    for _ in range(r.randint(2, 6)):
        d = r.choice(
            [
                base64.b64encode,
                lambda x: gzip.compress(x, mtime=0),
                lambda x: x.hex().encode(),
            ]
        )(d)
    return d


MUTATORS = [
    m_flip,
    m_byte,
    m_insert,
    m_delete,
    m_dup,
    m_truncate,
    m_b64,
    m_gzip,
    m_zip,
    m_host,
    m_nested,
]


# ----------------------------------------------------------------- execution
@contextlib.contextmanager
def argv(args):
    saved = sys.argv
    sys.argv = ["titan"] + args
    try:
        yield
    finally:
        sys.argv = saved


def run_cli(data: bytes, work: Path, variant: int) -> dict:
    sample = work / "in.bin"
    sample.write_bytes(data)
    gfmt = ["json", "dot", "mermaid"][variant % 3]
    ifmt = ["json", "csv", "stix", "misp"][variant % 4]
    rfmt = ["markdown", "html"][variant % 2]
    tfmt = ["json", "csv"][variant % 2]
    outs = {
        "report": work / "report.json",
        "intel": work / "intel.json",
        "graph": work / f"graph.{gfmt}",
        "ioc": work / f"iocs.{ifmt}",
        "case": work / f"case.{rfmt}",
        "timeline": work / f"timeline.{tfmt}",
        "jsonl": work / "r.jsonl",
    }
    for p in outs.values():
        if p.exists():
            p.unlink()
    args = [
        "--file",
        str(sample),
        "--offline",
        "--enable-detections",
        "--quiet",
        "--stdout",
        "none",
        "--strict",
        "--explain",
        "--out",
        str(outs["report"]),
        "--intelligence-out",
        str(outs["intel"]),
        "--graph",
        str(outs["graph"]),
        "--graph-format",
        gfmt,
        "--ioc-out",
        str(outs["ioc"]),
        "--ioc-format",
        ifmt,
        "--report-out",
        str(outs["case"]),
        "--report-format",
        rfmt,
        "--timeline-out",
        str(outs["timeline"]),
        "--timeline-format",
        tfmt,
        "--jsonl-out",
        str(outs["jsonl"]),
    ]
    code = 0
    with (
        argv(args),
        contextlib.redirect_stdout(io.StringIO()),
        contextlib.redirect_stderr(io.StringIO()) as err,
    ):
        try:
            cli.main()
        except SystemExit as exc:
            code = (
                exc.code
                if isinstance(exc.code, int)
                else (0 if exc.code is None else 1)
            )
    return {
        "code": code,
        "outs": outs,
        "fmt": (gfmt, ifmt, rfmt, tfmt),
        "stderr": err.getvalue(),
    }


def check(data: bytes, work: Path, variant: int) -> list[str]:
    problems: list[str] = []
    res = run_cli(data, work, variant)
    outs = res["outs"]
    if res["code"] not in (0,):
        problems.append(
            f"exit:{res['code']}:{res['stderr'].strip().splitlines()[-1][:160] if res['stderr'].strip() else ''}"
        )
    if not outs["report"].exists():
        problems.append("no-report")
        return problems
    try:
        report = json.loads(outs["report"].read_text())
    except Exception as exc:
        problems.append(f"report-json:{type(exc).__name__}")
        return problems

    # Schema
    try:
        jsonschema.validate(report, SCHEMA)
    except jsonschema.ValidationError as exc:
        problems.append(
            f"schema:{'/'.join(map(str, exc.absolute_path))}:{exc.message[:120]}"
        )

    # Graph integrity
    nodes = report.get("nodes", [])
    ids = [n.get("id") for n in nodes]
    if ids != list(range(len(nodes))):
        problems.append("node-ids-not-sequential")
    if report.get("node_count") != len(nodes):
        problems.append("node_count-mismatch")
    by_id = {n["id"]: n for n in nodes}
    for n in nodes:
        p = n.get("parent")
        if p is not None:
            if p not in by_id or p >= n["id"]:
                problems.append("bad-parent")
            prov = n.get("provenance") or {}
            if prov.get("parent_sha256") and by_id.get(p, {}).get("sha256") != prov.get(
                "parent_sha256"
            ):
                problems.append("provenance-parent-hash-mismatch")
            if n.get("depth") != by_id.get(p, {}).get("depth", -99) + 1:
                problems.append("depth-not-parent-plus-one")
        elif n["id"] != 0:
            problems.append("orphan-non-root")
    for n in nodes:
        if len(n.get("content_preview", "")) > 2000:
            problems.append("preview-over-2000")

    # IOC sanity
    iocs = report.get("iocs", {})
    for u in iocs.get("urls", []):
        if not u.lower().startswith(("http://", "https://")):
            problems.append("url-without-scheme")
    for key in ("ipv4", "ipv4_public", "ipv4_private"):
        for ip in iocs.get(key, []):
            parts = ip.split(".")
            if len(parts) != 4 or not all(x.isdigit() and int(x) <= 255 for x in parts):
                problems.append(f"invalid-{key}")
    for dom in iocs.get("domains", []):
        if dom != dom.lower() or ".." in dom or dom.startswith(".") or len(dom) > 253:
            problems.append("malformed-domain")
    for key, values in iocs.items():
        if values != sorted(set(values)):
            problems.append(f"ioc-not-sorted-unique:{key}")

    # Each output parses / is non-empty
    gfmt, ifmt, rfmt, tfmt = res["fmt"]
    for key in ("intel", "graph", "ioc", "case", "timeline", "jsonl"):
        p = outs[key]
        if not p.exists():
            problems.append(f"missing-output:{key}")
            continue
        text = p.read_text(encoding="utf-8", errors="strict")
        try:
            if (
                key == "intel"
                or (key == "graph" and gfmt == "json")
                or (key == "ioc" and ifmt in ("json", "stix", "misp"))
                or (key == "timeline" and tfmt == "json")
            ):
                json.loads(text)
            elif key in ("ioc", "timeline"):
                list(csv.reader(io.StringIO(text)))
            elif key == "jsonl":
                for line in text.splitlines():
                    if line.strip():
                        json.loads(line)
            elif key == "case" and not text.strip():
                problems.append("empty-case-report")
        except Exception as exc:
            problems.append(
                f"bad-output:{key}/{gfmt if key == 'graph' else ifmt if key == 'ioc' else tfmt if key == 'timeline' else rfmt}:{type(exc).__name__}"
            )

    # Determinism: second run, normalized compare
    res2 = run_cli(data, work, variant)
    try:
        r2 = json.loads(res2["outs"]["report"].read_text())

        def norm(r):
            r = json.loads(json.dumps(r))
            for k in list(r.get("meta", {})):
                if k in VOLATILE_META:
                    r["meta"].pop(k)
            r.pop("run_manifest", None)
            return r

        if norm(report) != norm(r2):
            diff = sorted(
                k
                for k in set(report) | set(r2)
                if norm(report).get(k) != norm(r2).get(k)
            )
            problems.append(f"nondeterministic:{','.join(diff)}")
    except Exception as exc:
        problems.append(f"rerun-failed:{type(exc).__name__}")

    # Analyst: deterministic answers must satisfy the validator.
    try:
        analyst = AnalystEngine([report])
        for q in QUESTIONS:
            resp = analyst.ask(q)
            v = validate_answer(resp.answer, analyst.index)
            if not v.ok:
                problems.append(
                    f"analyst-deterministic-fails-validation:{q[:25]}:inv={len(v.invalid)}"
                    f",uncited={len(v.uncited_claim_lines)},unsupported={len(v.unsupported_claim_lines)}"
                )
    except Exception as exc:
        problems.append(f"analyst-crash:{type(exc).__name__}:{str(exc)[:80]}")
    return problems


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seconds", type=float, default=600)
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument("--artifacts", default=".fuzz-artifacts")
    args = parser.parse_args()
    budget, seed = args.seconds, args.seed
    r = random.Random(seed)
    seeds = load_seeds()
    print(f"seeds: {len(seeds)}", flush=True)
    findings: dict[str, dict] = {}
    out_dir = Path(args.artifacts) / "e2e"
    out_dir.mkdir(parents=True, exist_ok=True)
    deadline = time.monotonic() + budget
    runs = 0
    # Pass 1: every seed unmutated; then mutated until the budget runs out.
    queue = [(name, data, "seed") for name, data in seeds]
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        while time.monotonic() < deadline:
            if queue:
                name, data, how = queue.pop(0)
            else:
                name, base = r.choice(seeds)
                data = base
                how = []
                for _ in range(r.randint(1, 3)):
                    m = r.choice(MUTATORS)
                    try:
                        data = m(r, data) or data
                    except Exception:
                        continue
                    how.append(m.__name__)
                how = "+".join(how)
                data = data[: 2 * 1024 * 1024]
            if not data:
                continue
            runs += 1
            signal.alarm(PER_INPUT_TIMEOUT)
            started = time.perf_counter()
            try:
                problems = check(data, work, runs)
            except Timeout:
                problems = ["TIMEOUT"]
            except Exception as exc:
                problems = [
                    f"HARNESS-OR-ESCAPE:{type(exc).__name__}:{str(exc)[:100]}|{traceback.format_exc()[-600:]}"
                ]
            finally:
                signal.alarm(0)
            elapsed = time.perf_counter() - started
            if elapsed > 20:
                problems.append(f"slow:{elapsed:.0f}s")
            for prob in problems:
                sig = prob.split("|")[0]
                sig = (
                    ":".join(sig.split(":")[:2])
                    if not sig.startswith(("analyst-", "schema", "exit"))
                    else sig[:140]
                )
                if sig not in findings:
                    digest = hashlib.sha256(data).hexdigest()[:16]
                    (out_dir / f"{digest}.bin").write_bytes(data)
                    findings[sig] = {
                        "first": prob[:900],
                        "seed": name,
                        "mutations": how,
                        "repro": f"{digest}.bin",
                        "count": 0,
                        "size": len(data),
                    }
                    print(
                        f"[run {runs}] NEW {sig}  <- {name} {how} ({len(data)}B)",
                        flush=True,
                    )
                findings[sig]["count"] += 1
            if runs % 50 == 0:
                print(f"... {runs} runs, {len(findings)} unique findings", flush=True)
    (out_dir / "summary.json").write_text(json.dumps(findings, indent=2))
    print(f"\nDONE: {runs} runs, {len(findings)} unique findings", flush=True)
    for sig, f in sorted(findings.items(), key=lambda kv: -kv[1]["count"]):
        print(f"  {f['count']:>5}x  {sig}")
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
