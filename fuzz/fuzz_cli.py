#!/usr/bin/env python3
"""CLI-mode campaign: the CLI paths fuzz_e2e.py does not drive.

batch, deep-scan (+supervised, +quarantine), supervised single-file,
correlation DB + every correlation export, vault store/search, evidence
ingestion (mutated CSV/JSONL for every kind), forensics, redaction, profiles,
max-depth. Invariants: no escaped exception, no traceback on stderr, exit code
in the documented set, every requested output exists and parses, copy-mode
quarantine never alters a source, supervised output matches in-process.

    python fuzz/fuzz_cli.py --seconds 600 --seed 11 --artifacts .fuzz-artifacts

Exits 1 when any finding is recorded.
"""

from __future__ import annotations

import contextlib
import csv
import hashlib
import io
import json
import os
import random
import shutil
import signal
import sys
import tempfile
import time
import traceback
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import fuzz_e2e as base  # noqa: E402  (sets sys.path, alarm handler, logging off)

from titan_decoder import cli  # noqa: E402

KINDS = ["dns", "proxy", "firewall", "vpn", "auth", "dhcp", "generic"]
FIELDS = [
    "timestamp",
    "time",
    "ts",
    "src_ip",
    "dst_ip",
    "client_ip",
    "query",
    "domain",
    "url",
    "host",
    "user",
    "action",
    "answers",
    "dst_port",
    "bytes",
    "mac",
    "status",
    "_line",
    "raw",
]
TIMEOUT = 300


def run(args: list[str], home: Path) -> tuple[int, str, str, BaseException | None]:
    code = 0
    escaped = None
    os.environ["HOME"] = str(home)
    out, err = io.StringIO(), io.StringIO()
    with (
        base.argv(args),
        contextlib.redirect_stdout(out),
        contextlib.redirect_stderr(err),
    ):
        try:
            cli.main()
        except SystemExit as exc:
            code = (
                exc.code
                if isinstance(exc.code, int)
                else (0 if exc.code is None else 1)
            )
        except base.Timeout:
            raise
        except BaseException as exc:  # noqa: BLE001
            escaped = exc
            code = -1
            err.write(traceback.format_exc())
    return code, out.getvalue(), err.getvalue(), escaped


def junk_value(r: random.Random, iocs: list[str]):
    pick = r.random()
    if iocs and pick < 0.35:
        return r.choice(iocs)
    return r.choice(
        [
            "",
            None,
            0,
            -1,
            2**70,
            1.5e308,
            "nan",
            True,
            [],
            {},
            ["1.2.3.4", None],
            {"a": [1]},
            "2024-02-30T25:61:61Z",
            "1700000000",
            "99999999999999999999",
            "\x00\x01",
            "a" * r.randint(1, 5000),
            "999.1.1.1",
            "evil.example.com",
            "http://[::1",
            "%zz",
            "Ω" * 30,
            "1.2.3.4,5.6.7.8;;",
            "-",
            "  ",
            "10.0.0.1:65536",
            "ff:ff:ff:ff:ff:ff",
            "=cmd|' /C calc'!A0",
        ]
    )


def evidence_file(r: random.Random, path: Path, iocs: list[str]) -> None:
    rows = []
    for i in range(r.randint(0, 40)):
        rec = {
            f: junk_value(r, iocs) for f in r.sample(FIELDS, r.randint(0, len(FIELDS)))
        }
        rows.append(rec)
    if path.suffix == ".csv":
        cols = sorted({k for row in rows for k in row}) or ["x"]
        buf = io.StringIO()
        w = csv.DictWriter(buf, fieldnames=cols, extrasaction="ignore")
        if r.random() < 0.9:
            w.writeheader()
        for row in rows:
            w.writerow(
                {
                    k: (json.dumps(v) if isinstance(v, (list, dict)) else v)
                    for k, v in row.items()
                }
            )
        text = buf.getvalue()
    else:
        lines = [json.dumps(row) for row in rows]
        if r.random() < 0.3:
            lines.insert(
                r.randint(0, len(lines)),
                r.choice(["{", "[]", "null", '"s"', "1", '{"a":', "﻿{}"]),
            )
        text = "\n".join(lines)
    data = text.encode("utf-8", "surrogatepass")
    if r.random() < 0.3 and data:
        data = base.m_flip(r, data)
    path.write_bytes(data)


def parses(path: Path, kind: str) -> str | None:
    if not path.exists():
        return "missing"
    try:
        text = path.read_text(encoding="utf-8")
        if kind == "json":
            json.loads(text)
        elif kind == "jsonl":
            for line in text.splitlines():
                if line.strip():
                    json.loads(line)
        elif kind == "csv":
            list(csv.reader(io.StringIO(text)))
    except Exception as exc:  # noqa: BLE001
        return f"{type(exc).__name__}"
    return None


def scenario(r: random.Random, samples: list[bytes], work: Path) -> list[str]:
    problems: list[str] = []
    home = work / "home"
    home.mkdir()
    sdir = work / "samples"
    sdir.mkdir()
    for i, data in enumerate(samples):
        (
            sdir / f"s{i}.{r.choice(['bin', 'js', 'txt', 'eml', 'zip', 'docx'])}"
        ).write_bytes(data)
    if r.random() < 0.3:
        (sdir / "sub").mkdir()
        (sdir / "sub" / "deep.bin").write_bytes(r.choice(samples))
    files = sorted(p for p in sdir.rglob("*") if p.is_file())
    common = ["--offline", "--quiet"]
    if r.random() < 0.5:
        common += ["--profile", r.choice(["safe", "fast", "full"])]
    if r.random() < 0.3:
        common += ["--max-depth", str(r.choice([0, 1, 2, 50]))]

    def note(label: str, res, allowed=(0,)):
        code, out, err, escaped = res
        if escaped is not None:
            problems.append(
                f"{label}:escaped:{type(escaped).__name__}:{str(escaped)[:80]}|{err[-800:]}"
            )
        elif code not in allowed:
            tail = err.strip().splitlines()[-1][:140] if err.strip() else ""
            problems.append(f"{label}:exit{code}:{tail}")
        if "Traceback (most recent call last)" in err and escaped is None:
            problems.append(f"{label}:traceback-on-stderr|{err[-800:]}")

    choice = r.choice(
        [
            "batch",
            "deep",
            "deep-sup",
            "supervised",
            "correlation",
            "vault",
            "evidence",
            "misc",
        ]
    )

    if choice == "batch":
        out = work / "batch_reports"
        note(
            "batch",
            run(
                ["--batch", str(sdir), "--out", str(out), "--enable-detections"]
                + common,
                home,
            ),
        )
        reports = sorted(out.glob("*.json")) if out.is_dir() else []
        if len(reports) < len([f for f in files if f.parent == sdir]):
            problems.append(f"batch:only-{len(reports)}-reports-for-{len(files)}")
        for rp in reports:
            if bad := parses(rp, "json"):
                problems.append(f"batch:report-{bad}")

    elif choice in ("deep", "deep-sup"):
        reports, qdir, summary = work / "reports", work / "q", work / "deep.json"
        args = [
            "--deep-scan",
            str(sdir),
            "--deep-scan-reports",
            str(reports),
            "--deep-scan-out",
            str(summary),
            "--quarantine-dir",
            str(qdir),
            "--quarantine-verdict",
            r.choice(["malicious", "suspicious"]),
            "--quarantine-action",
            "copy",
        ] + common
        if choice == "deep-sup":
            args.append("--deep-scan-supervised")
        before = {p: p.read_bytes() for p in files}
        note(choice, run(args, home), allowed=(0, 1, 2))
        if bad := parses(summary, "json"):
            problems.append(f"{choice}:summary-{bad}")
        for p, data in before.items():
            if not p.exists() or p.read_bytes() != data:
                problems.append(f"{choice}:copy-quarantine-mutated-source")
        if reports.exists():
            for rp in reports.rglob("*.json"):
                if bad := parses(rp, "json"):
                    problems.append(f"{choice}:report-{bad}")
        note(
            "quarantine-list",
            run(["--quarantine-list", "--quarantine-dir", str(qdir), "--quiet"], home),
            allowed=(0,),
        )

    elif choice == "supervised":
        f = r.choice(files)
        out = work / "sup.json"
        note(
            "supervised",
            run(
                [
                    "--file",
                    str(f),
                    "--supervised",
                    "--out",
                    str(out),
                    "--enable-detections",
                    "--stdout",
                    "none",
                ]
                + common,
                home,
            ),
            allowed=(0, 1, 2, 3),
        )
        if out.exists() and (bad := parses(out, "json")):
            problems.append(f"supervised:out-{bad}")
        elif out.exists():
            base_out = work / "inproc.json"
            run(
                [
                    "--file",
                    str(f),
                    "--out",
                    str(base_out),
                    "--enable-detections",
                    "--stdout",
                    "none",
                ]
                + common,
                home,
            )
            try:
                a, b = json.loads(out.read_text()), json.loads(base_out.read_text())
                if a.get("analysis_outcome", {}).get("status") == "complete" and [
                    n["sha256"] for n in a["nodes"]
                ] != [n["sha256"] for n in b["nodes"]]:
                    problems.append("supervised:diverges-from-in-process")
            except Exception as exc:  # noqa: BLE001
                problems.append(f"supervised:compare-{type(exc).__name__}")

    elif choice == "correlation":
        db = work / "corr.sqlite3"
        for i, f in enumerate(files[: r.randint(1, len(files))]):
            outs = {
                k: work / f"{k}{i}.json"
                for k in ("corr", "camp", "tl", "infra", "shared", "attr", "an")
            }
            args = [
                "--file",
                str(f),
                "--correlation-db",
                str(db),
                "--correlation-out",
                str(outs["corr"]),
                "--campaign-out",
                str(outs["camp"]),
                "--timeline-correlation-out",
                str(outs["tl"]),
                "--infrastructure-reuse-out",
                str(outs["infra"]),
                "--shared-payload-out",
                str(outs["shared"]),
                "--attribution-hints-out",
                str(outs["attr"]),
                "--analyst-correlation-out",
                str(outs["an"]),
                "--analyst-correlation-format",
                "json",
                "--stdout",
                "none",
                "--enable-detections",
            ] + common
            invalid = False
            if r.random() < 0.2:
                score = r.choice(["0", "1", "-5", "1e9", "0.5", "nan"])
                invalid = score in ("-5", "1e9", "nan")
                args += ["--correlation-min-score", score]
            res = run(args, home)
            if invalid:
                if res[0] == 0 or res[3] is not None:
                    problems.append(
                        f"correlation:invalid-min-score-accepted-or-crashed:{res[0]}"
                    )
                continue
            note("correlation", res)
            for k, p in outs.items():
                if bad := parses(p, "json"):
                    problems.append(f"correlation:{k}-{bad}")
        q = r.choice(
            [
                "evil.example.com",
                "1.2.3.4",
                "domain:x",
                "sha256:" + "a" * 64,
                "",
                "%",
                "'; DROP TABLE x;--",
                "url:http://a",
                "ipv4:999.1.1.1",
                ":",
                "unknowntype:v",
            ]
        )
        note(
            "correlation-search",
            run(
                ["--correlation-db", str(db), "--correlation-search", q, "--quiet"],
                home,
            ),
            allowed=(0, 1, 2),
        )

    elif choice == "vault":
        for f in files[: r.randint(1, len(files))]:
            note(
                "vault-store",
                run(
                    ["--file", str(f), "--vault-store", "--stdout", "none"] + common,
                    home,
                ),
            )
        for q in (
            r.choice(["1.2.3.4", "", "%", "_", "a" * 3000, "evil.example.com", "\x00"]),
        ):
            note(
                "vault-search",
                run(["--vault-search", q, "--quiet"], home),
                allowed=(0, 1, 2),
            )
        note(
            "vault-recent",
            run(
                ["--vault-list-recent", str(r.choice([0, 1, 10, -1])), "--quiet"], home
            ),
            allowed=(0, 1, 2),
        )
        note(
            "vault-prune",
            run(
                ["--vault-prune-days", str(r.choice([0, 1, 365, -3])), "--quiet"], home
            ),
            allowed=(0, 1, 2),
        )

    elif choice == "evidence":
        f = r.choice(files)
        pre = work / "pre.json"
        run(["--file", str(f), "--out", str(pre), "--stdout", "none"] + common, home)
        iocs: list[str] = []
        try:
            for vals in json.loads(pre.read_text()).get("iocs", {}).values():
                iocs.extend(vals)
        except Exception:  # noqa: BLE001
            pass
        args = ["--file", str(f), "--stdout", "none", "--enable-detections"] + common
        for j in range(r.randint(1, 4)):
            kind = r.choice(KINDS)
            ep = work / f"ev{j}.{r.choice(['csv', 'jsonl', 'ndjson'])}"
            evidence_file(r, ep, iocs)
            args += ["--evidence", f"{kind}:{ep}"]
        fmt = r.choice(["json", "csv"])
        out, etl = work / "ev_report.json", work / f"etl.{fmt}"
        args += [
            "--out",
            str(out),
            "--evidence-timeline-out",
            str(etl),
            "--evidence-timeline-format",
            fmt,
        ]
        note("evidence", run(args, home), allowed=(0, 1, 2))
        if out.exists() and (bad := parses(out, "json")):
            problems.append(f"evidence:report-{bad}")
        if out.exists() and (bad := parses(etl, fmt)):
            problems.append(f"evidence:timeline-{bad}")

    else:
        f = r.choice(files)
        out, fo, prof = work / "m.json", work / "forensics.json", work / "profile.json"
        args = [
            "--file",
            str(f),
            "--out",
            str(out),
            "--forensics-out",
            str(fo),
            "--stdout",
            "json",
            "--enable-detections",
            "--explain",
            "--trace",
            "--perf-profile",
            "--profile-out",
            str(prof),
            "--max-artifacts",
            str(r.choice([0, 1, 5, 1000])),
        ] + common
        if r.random() < 0.5:
            args.append("--enable-redaction")
        if r.random() < 0.3:
            args += [
                "--fail-on-risk-level",
                r.choice(["medium", "HIGH", "Critical"]),
            ]
        res = run(args, home)
        note("misc", res, allowed=(0, 1, 2, 3, 4, 10, 11, 12, 13))
        for name, p in (("report", out), ("forensics", fo), ("profile", prof)):
            if bad := parses(p, "json"):
                problems.append(f"misc:{name}-{bad}")
        if res[1].strip():
            try:
                json.loads(res[1])
            except Exception:  # noqa: BLE001
                problems.append("misc:stdout-json-invalid")
        if "--enable-redaction" in args and out.exists():
            text = out.read_text()
            if "@" in text and any(t in text for t in ("password=", "Password:")):
                problems.append("misc:redaction-leak?")
    return [f"[{choice}] {p}" for p in problems]


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seconds", type=float, default=600)
    parser.add_argument("--seed", type=int, default=11)
    parser.add_argument("--artifacts", default=".fuzz-artifacts")
    args = parser.parse_args()
    budget, seed = args.seconds, args.seed
    r = random.Random(seed)
    seeds = base.load_seeds()
    out_dir = Path(args.artifacts) / "cli"
    out_dir.mkdir(parents=True, exist_ok=True)
    findings: dict[str, dict] = {}
    deadline = time.monotonic() + budget
    runs = 0
    while time.monotonic() < deadline:
        samples = []
        for _ in range(r.randint(1, 5)):
            data = r.choice(seeds)[1]
            for _ in range(r.randint(0, 2)):
                try:
                    data = r.choice(base.MUTATORS)(r, data) or data
                except Exception:  # noqa: BLE001
                    pass
            samples.append(data[: 512 * 1024] or b"x")
        runs += 1
        work = Path(tempfile.mkdtemp())
        signal.alarm(TIMEOUT)
        try:
            problems = scenario(r, samples, work)
        except base.Timeout:
            problems = ["TIMEOUT"]
        except Exception as exc:  # noqa: BLE001
            problems = [
                f"HARNESS:{type(exc).__name__}:{str(exc)[:100]}|{traceback.format_exc()[-600:]}"
            ]
        finally:
            signal.alarm(0)
            shutil.rmtree(work, ignore_errors=True)
        for prob in problems:
            sig = prob.split("|")[0][:160]
            if sig not in findings:
                digest = hashlib.sha256(b"".join(samples)).hexdigest()[:16]
                for i, s in enumerate(samples):
                    (out_dir / f"{digest}_{i}.bin").write_bytes(s)
                findings[sig] = {
                    "first": prob[:1500],
                    "repro": digest,
                    "count": 0,
                    "rng_run": runs,
                }
                print(f"[run {runs}] NEW {sig}", flush=True)
            findings[sig]["count"] += 1
        if runs % 20 == 0:
            print(f"... {runs} scenarios, {len(findings)} unique", flush=True)
    (out_dir / "summary.json").write_text(json.dumps(findings, indent=2))
    print(f"\nDONE: {runs} scenarios, {len(findings)} unique findings", flush=True)
    for sig, f in sorted(findings.items(), key=lambda kv: -kv[1]["count"]):
        print(f"  {f['count']:>5}x  {sig}")
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
