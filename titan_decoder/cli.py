#!/usr/bin/env python3

import argparse
import json
import sys
import random
from pathlib import Path
from typing import Any

from . import __version__ as TITAN_VERSION
from .core.engine import TitanEngine
from .core.device_forensics import ForensicsEngine
from .config import Config
from .core.offline_guard import block_network, is_network_blocked
from .core.evidence_parsers import parse_evidence_file, combine_parse_results
from .core.evidence_correlation import top_pivots, build_last_seen, build_entity_hints
from .core.evidence_links import build_links_from_evidence_events, top_links
from .optional_formats import optional_format_status


def build_parser() -> argparse.ArgumentParser:
    """Construct the CLI argument parser (thin, side-effect-free)."""
    parser = argparse.ArgumentParser(
        description="Titan Decoder Engine - Advanced payload analysis tool"
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"titan {TITAN_VERSION}",
    )
    parser.add_argument(
        "--interactive",
        "-i",
        action="store_true",
        help="Launch the interactive menu-driven UI (same as the 'titan' command)",
    )
    parser.add_argument("--file", "-f", type=Path, help="Input file to analyze")
    parser.add_argument(
        "--batch", type=Path, help="Directory containing files to analyze in batch mode"
    )
    parser.add_argument(
        "--batch-pattern", default="*", help="Glob pattern for batch mode (default: *)"
    )
    parser.add_argument(
        "--deep-scan",
        type=Path,
        help="Recursively analyze a file or directory without executing samples",
    )
    parser.add_argument(
        "--deep-scan-supervised",
        action="store_true",
        help="Run offline deep-scan parsing and static checks in a resource-limited worker",
    )
    parser.add_argument(
        "--deep-scan-pattern",
        default="*",
        help="Glob pattern for recursive deep scanning (default: *)",
    )
    parser.add_argument(
        "--deep-scan-reports",
        type=Path,
        help="Directory for per-file deep-scan reports",
    )
    parser.add_argument(
        "--deep-scan-out",
        type=Path,
        help="Write the deep-scan summary JSON to this file",
    )
    parser.add_argument(
        "--quarantine-dir",
        type=Path,
        help="Recoverable quarantine vault (default: ~/.titan_decoder/quarantine)",
    )
    parser.add_argument(
        "--quarantine-verdict",
        action="append",
        choices=["malicious", "suspicious"],
        help=(
            "Quarantine matching deep-scan verdicts; repeat to include both. "
            "No files are quarantined unless this option is supplied."
        ),
    )
    parser.add_argument(
        "--quarantine-action",
        choices=["copy", "move"],
        default="copy",
        help="Copy to quarantine (default) or move after a verified vault copy",
    )
    parser.add_argument(
        "--quarantine-list",
        action="store_true",
        help="List recoverable quarantine records as JSON and exit",
    )
    parser.add_argument(
        "--quarantine-restore",
        metavar="RECORD_ID",
        help="Restore one quarantine record and exit",
    )
    parser.add_argument(
        "--quarantine-destination",
        type=Path,
        help="Destination for --quarantine-restore (default: original path)",
    )
    parser.add_argument(
        "--quarantine-overwrite",
        action="store_true",
        help="Allow an explicit quarantine restore to replace its destination",
    )
    parser.add_argument(
        "--calibrate",
        type=Path,
        metavar="CORPUS_JSON",
        help="Evaluate decoder/analyzer precision and recall on a labeled corpus",
    )
    parser.add_argument(
        "--calibration-out",
        type=Path,
        help="Write the calibration report to this JSON file",
    )
    parser.add_argument("--out", "-o", type=Path, help="Output JSON report file")
    parser.add_argument(
        "--trace",
        action="store_true",
        help="Include per-step decision trace in JSON report (larger output)",
    )
    parser.add_argument(
        "--jsonl-out",
        type=Path,
        help="Write newline-delimited JSON events (nodes/detections/meta)",
    )
    parser.add_argument(
        "--stdout",
        choices=["json", "none"],
        default="json",
        help="Control stdout output when --out is not set (default: json)",
    )
    parser.add_argument(
        "--print-schema-version",
        action="store_true",
        help="Print the current report schema version as JSON and exit",
    )
    parser.add_argument(
        "--list-decoders",
        action="store_true",
        help="List available/enabled decoders as JSON and exit",
    )
    parser.add_argument(
        "--list-analyzers",
        action="store_true",
        help="List available/enabled analyzers as JSON and exit",
    )
    parser.add_argument(
        "--list-rule-packs",
        action="store_true",
        help="List configured detection rule packs and exit",
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Enable verbose logging"
    )
    parser.add_argument(
        "--log-json",
        action="store_true",
        help="Emit logs as JSON lines (useful for ingestion)",
    )
    parser.add_argument(
        "--seed",
        type=int,
        help="Deterministic seed (recorded in run_manifest)",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Fail non-zero if the report violates the expected contract",
    )
    parser.add_argument(
        "--max-report-size-mb",
        type=float,
        help="Fail if the JSON report exceeds this size (guards huge outputs)",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress non-error status output (keeps output clean)",
    )
    parser.add_argument(
        "--doctor",
        action="store_true",
        help="Run self-checks and print a JSON diagnostic report",
    )
    parser.add_argument(
        "--vault-store",
        action="store_true",
        help="Store the report in a local vault and index IOCs for later search",
    )
    parser.add_argument(
        "--vault-search",
        type=str,
        help="Search the local vault for an exact IOC/indicator value and exit",
    )
    parser.add_argument(
        "--vault-search-type",
        type=str,
        help="Optional IOC type filter for --vault-search (e.g., urls, ipv4_public)",
    )
    parser.add_argument(
        "--vault-list-recent",
        type=int,
        help="List recent vault runs as JSON and exit",
    )
    parser.add_argument(
        "--vault-prune-days",
        type=int,
        help="Delete vault entries older than N days and exit",
    )
    parser.add_argument(
        "--max-depth", type=int, help="Maximum recursion depth (overrides config)"
    )
    parser.add_argument("--config", type=Path, help="Configuration file path")
    parser.add_argument("--graph", type=Path, help="Export analysis graph to file")
    parser.add_argument(
        "--graph-format",
        choices=["json", "dot", "mermaid"],
        default="json",
        help="Graph export format (default: json)",
    )
    parser.add_argument(
        "--perf-profile",
        action="store_true",
        help="Enable performance profiling with cProfile",
    )
    parser.add_argument(
        "--profile-out", type=Path, help="Save performance profile output to file"
    )
    parser.add_argument(
        "--forensics-out",
        type=Path,
        help="Save forensic attribution summary to JSON file",
    )
    parser.add_argument(
        "--forensics-print",
        action="store_true",
        help="Print forensic attribution summary to stdout",
    )
    parser.add_argument(
        "--ioc-out", type=Path, help="Export IOCs to file (use with --ioc-format)"
    )
    parser.add_argument(
        "--ioc-format",
        choices=["json", "csv", "stix", "misp"],
        default="json",
        help="IOC export format (json, csv, stix, misp)",
    )
    parser.add_argument(
        "--report-out", type=Path, help="Save case report (use with --report-format)"
    )
    parser.add_argument(
        "--report-format",
        choices=["markdown", "html"],
        default="markdown",
        help="Case report format (default: markdown)",
    )
    parser.add_argument(
        "--evidence",
        action="append",
        type=str,
        help=(
            "Add IR evidence input as KIND:PATH (can be repeated). "
            "KIND: dns|proxy|firewall|vpn|auth|dhcp|generic. "
            "Supports .csv or .jsonl/.ndjson."
        ),
    )
    parser.add_argument("--timeline-out", type=Path, help="Export analysis timeline")
    parser.add_argument(
        "--timeline-format",
        choices=["json", "csv"],
        default="json",
        help="Timeline export format (json, csv)",
    )
    parser.add_argument(
        "--evidence-timeline-out",
        type=Path,
        help="Export normalized evidence timeline (from --evidence inputs)",
    )
    parser.add_argument(
        "--evidence-timeline-format",
        choices=["json", "csv"],
        default="json",
        help="Evidence timeline export format (json, csv)",
    )
    parser.add_argument(
        "--profile",
        choices=["safe", "fast", "full"],
        dest="analysis_profile",
        help="Analysis profile: 'safe' for hostile inputs, 'fast' for triage, 'full' for deep analysis",
    )
    parser.add_argument(
        "--max-artifacts",
        type=int,
        help="Maximum number of artifacts to extract (overrides config)",
    )
    parser.add_argument(
        "--progress",
        action="store_true",
        help="Show progress information during analysis",
    )
    parser.add_argument(
        "--enable-enrichment",
        action="store_true",
        help="Enable geo/WHOIS/YARA enrichment (requires config)",
    )
    parser.add_argument(
        "--enrichment-cache-path",
        type=Path,
        help="Path to SQLite enrichment cache DB (default: ~/.titan_decoder/enrichment_cache.db)",
    )
    parser.add_argument(
        "--refresh-enrichment",
        action="store_true",
        help="Bypass enrichment cache and re-query providers (where applicable)",
    )
    parser.add_argument(
        "--offline",
        action="store_true",
        help="Force offline mode (disables all network enrichment regardless of config)",
    )
    parser.add_argument(
        "--enable-detections",
        action="store_true",
        help="Run detection rules and compute risk score",
    )
    parser.add_argument(
        "--explain",
        action="store_true",
        help=(
            "Print a human-readable Titan intelligence explanation to stderr "
            "while preserving JSON stdout"
        ),
    )
    parser.add_argument(
        "--intelligence-out",
        type=Path,
        help="Write the intelligence summary to a separate JSON file",
    )
    parser.add_argument(
        "--plugin-dir",
        action="append",
        type=Path,
        help="Additional plugin directory to load (repeatable)",
    )
    parser.add_argument(
        "--plugin-validate",
        action="append",
        type=Path,
        help="Validate a manifest plugin directory and exit (repeatable)",
    )
    parser.add_argument(
        "--plugin-list",
        action="store_true",
        help="List discovered plugins (including load errors) and exit",
    )
    parser.add_argument(
        "--rules-pack",
        action="append",
        type=Path,
        help="Path to a detection rule pack (JSON/YAML). Can be repeated.",
    )
    parser.add_argument(
        "--rules-pack-dir",
        action="append",
        type=Path,
        help="Directory of detection rule packs to load (.json/.yml/.yaml). Can be repeated.",
    )
    parser.add_argument(
        "--yara-rules",
        action="append",
        type=Path,
        help=(
            "YARA rules file or directory of .yar/.yara files, scanned against "
            "every artifact-graph node (raw, decoded, and extracted content). "
            "Implies YARA scanning for the run; requires --enable-detections "
            "and the optional yara-python dependency. Can be repeated."
        ),
    )
    parser.add_argument(
        "--rules-validate",
        action="append",
        type=Path,
        help="Validate a rule pack file and exit (can be repeated)",
    )
    parser.add_argument(
        "--correlation-db",
        type=Path,
        help=(
            "Local SQLite database for Phase 5 cross-case correlation "
            "(default: ~/.titan_decoder/correlation.sqlite3)"
        ),
    )
    parser.add_argument(
        "--correlation-out",
        type=Path,
        help="Write the cross-case correlation report (relationships) to a JSON file",
    )
    parser.add_argument(
        "--correlation-search",
        action="append",
        metavar="[TYPE:]VALUE",
        help=(
            "Search the correlation database for an indicator across recorded "
            "cases and exit (repeatable). Prefix with an indicator type to "
            "restrict, e.g. domains:c2.example"
        ),
    )
    parser.add_argument(
        "--correlation-min-score",
        type=float,
        default=0.0,
        help="Minimum relationship score to include in the correlation report (0-1)",
    )
    parser.add_argument(
        "--correlation-no-record",
        action="store_true",
        help="Correlate against prior analyses without recording this one",
    )
    parser.add_argument(
        "--campaign-out",
        type=Path,
        help="Write campaign clusters over recorded analyses to a JSON file",
    )
    parser.add_argument(
        "--campaign-min-score",
        type=float,
        default=0.45,
        help="Minimum relationship score for campaign clustering edges (0-1)",
    )
    parser.add_argument(
        "--timeline-correlation-out",
        type=Path,
        help="Write cross-case timeline correlation links to a JSON file",
    )
    parser.add_argument(
        "--timeline-window-seconds",
        type=float,
        default=300.0,
        help="Time window for cross-case timeline correlation (seconds)",
    )
    parser.add_argument(
        "--infrastructure-reuse-out",
        type=Path,
        help="Write infrastructure reuse detections to a JSON file",
    )
    parser.add_argument(
        "--shared-payload-out",
        type=Path,
        help="Write shared payload detections to a JSON file",
    )
    parser.add_argument(
        "--shared-payload-min-score",
        type=float,
        default=0.35,
        help="Minimum similarity score for shared payload matches (0-1)",
    )
    parser.add_argument(
        "--attribution-hints-out",
        type=Path,
        help="Write evidence-backed attribution hints to a JSON file",
    )
    parser.add_argument(
        "--analyst-correlation-out",
        type=Path,
        help="Write the analyst correlation view to a file",
    )
    parser.add_argument(
        "--analyst-correlation-format",
        choices=["json", "markdown", "html"],
        default="json",
        help="Format for --analyst-correlation-out (default: json)",
    )
    parser.add_argument(
        "--fail-on-risk-level",
        choices=["MEDIUM", "HIGH", "CRITICAL"],
        help="Exit non-zero if risk_assessment risk_level is at/above this level",
    )
    parser.add_argument(
        "--enable-redaction",
        action="store_true",
        default=True,
        help="Enable PII redaction in logs (default: enabled)",
    )
    parser.add_argument(
        "--no-redaction",
        action="store_false",
        dest="enable_redaction",
        help="Disable PII redaction in logs",
    )
    return parser


def _parse_evidence_specs(specs: "list[str] | None"):
    """Parse ``--evidence KIND:PATH`` specs into a combined parse result."""
    if not specs:
        return None
    results = []
    for spec in specs:
        if not spec:
            continue
        if ":" not in spec:
            raise SystemExit(
                "--evidence must be in KIND:PATH form (e.g., dns:logs/dns.csv)"
            )
        kind, path_s = spec.split(":", 1)
        path = Path(path_s)
        if not path.exists():
            raise SystemExit(f"Evidence path not found: {path}")
        results.append(parse_evidence_file(path, kind))
    return combine_parse_results(results)


def apply_cli_config(args, config) -> None:
    """Apply CLI-level config overrides that must land before any early exit."""
    if args.trace:
        config.set("include_decision_trace", True)
    # CLI-level overrides that should be reflected in run_manifest.
    if args.seed is not None:
        random.seed(int(args.seed))
        config.set("seed", int(args.seed))
    if args.max_report_size_mb is not None:
        config.set("max_report_size_mb", float(args.max_report_size_mb))
    if args.strict:
        config.set("strict", True)


def handle_info_commands(args, config) -> "int | None":
    """Handle early-exit informational / vault subcommands.

    Returns an exit code if one of these commands handled the invocation, or
    ``None`` if normal analysis should proceed. Kept as one stage so main() is a
    thin dispatcher and each mode is independently testable.
    """
    # Print schema version and exit.
    if args.print_schema_version:
        from titan_decoder.core.engine import SCHEMA_VERSION

        print(json.dumps({"schema_version": SCHEMA_VERSION}))
        return 0

    if args.quarantine_list or args.quarantine_restore:
        from .core.quarantine import QuarantineVault

        configured = args.quarantine_dir or config.get("quarantine_dir")
        vault = QuarantineVault(Path(str(configured)) if configured else None)
        if args.quarantine_list:
            print(
                json.dumps(
                    {
                        "root": str(vault.root),
                        "records": [r.to_dict() for r in vault.records()],
                    },
                    indent=2,
                )
            )
            return 0
        try:
            destination = vault.restore(
                args.quarantine_restore,
                args.quarantine_destination,
                overwrite=bool(args.quarantine_overwrite),
            )
        except (OSError, KeyError, RuntimeError, ValueError) as exc:
            print(f"Error: quarantine restore failed: {exc}", file=sys.stderr)
            return 1
        print(
            json.dumps(
                {
                    "restored": True,
                    "record_id": args.quarantine_restore,
                    "destination": str(destination),
                },
                indent=2,
            )
        )
        return 0

    if args.calibrate:
        from .core.calibration import CalibrationRunner

        try:
            report = CalibrationRunner(config).run(args.calibrate)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            print(f"Error: calibration failed: {exc}", file=sys.stderr)
            return 1
        encoded = json.dumps(report, indent=2, sort_keys=True)
        if args.calibration_out:
            args.calibration_out.parent.mkdir(parents=True, exist_ok=True)
            args.calibration_out.write_text(encoded + "\n", encoding="utf-8")
        print(encoded)
        return 0 if report["quality_gate"]["passed"] else 1

    # List rule packs and exit.
    if args.list_rule_packs:
        packs = []
        for p in config.get("detection_rule_packs", []) or []:
            packs.append({"path": str(p), "exists": Path(p).exists()})
        print(json.dumps({"rule_packs": packs}, indent=2))
        return 0

    # Validate manifest plugins and exit. Deep validation: manifest contract,
    # API compatibility, entry point, capabilities, and a bounded runtime
    # probe. Note the probe executes plugin code in-process.
    if args.plugin_validate:
        from .plugins.validation import validate_plugins

        ok, results = validate_plugins(args.plugin_validate)
        print(json.dumps({"ok": ok, "results": results}, indent=2))
        return 0 if ok else 1

    # List discovered plugins (same directory set the engine uses) and exit.
    if args.plugin_list:
        from .plugins import PluginManager

        manager = PluginManager()
        for plugin_dir in config.get("plugin_dirs", []) or []:
            manager.add_plugin_dir(Path(plugin_dir))
        for plugin_dir in args.plugin_dir or []:
            manager.add_plugin_dir(Path(plugin_dir))
        manager.add_plugin_dir(Path.home() / ".titan_decoder" / "plugins")
        manager.add_plugin_dir(Path(__file__).parent / "plugins")
        manager.load_plugins()
        print(json.dumps(manager.get_plugin_info(), indent=2))
        return 0

    # Validate rule packs and exit. Deep validation: structural load errors,
    # the per-pack rule limit, per-rule definition problems, and duplicate ids
    # all surface as errors and fail the command.
    if args.rules_validate:
        from titan_decoder.core.rule_packs import validate_rule_pack

        results = [validate_rule_pack(Path(p)) for p in args.rules_validate]
        ok = all(r["ok"] for r in results)
        print(json.dumps({"ok": ok, "results": results}, indent=2))
        return 0 if ok else 1

    # List decoders/analyzers and exit.
    if args.list_decoders or args.list_analyzers:
        engine = TitanEngine(config)
        listing = {}
        if args.list_decoders:
            decs = [
                {
                    "name": getattr(d, "name", type(d).__name__),
                    "class": type(d).__name__,
                }
                for d in engine.decoders
            ]
            listing["decoders"] = sorted(decs, key=lambda x: x["name"])
        if args.list_analyzers:
            ans = [
                {
                    "name": getattr(a, "name", type(a).__name__),
                    "class": type(a).__name__,
                }
                for a in engine.analyzers
            ]
            listing["analyzers"] = sorted(ans, key=lambda x: x["name"])
        print(json.dumps(listing, indent=2))
        return 0

    # Doctor mode: run diagnostics and exit (no input file required).
    if args.doctor:
        diag = _run_doctor(config)
        print(json.dumps(diag, indent=2))
        return 0 if diag.get("ok") else 1

    # Vault prune/list/search modes (no input file required).
    if args.vault_prune_days is not None:
        result = _vault_prune(config, int(args.vault_prune_days))
        print(json.dumps(result, indent=2))
        return 0
    if args.vault_list_recent is not None:
        recent = _vault_list_recent(config, int(args.vault_list_recent))
        print(json.dumps({"recent": recent}, indent=2))
        return 0

    # Correlation search mode: query the Phase 5 cross-case IOC database and
    # exit (no input file required).
    if args.correlation_search:
        from .correlation.service import search_cases

        db_path = args.correlation_db or (
            Path.home() / ".titan_decoder" / "correlation.sqlite3"
        )
        try:
            result = search_cases(db_path, args.correlation_search)
        except (OSError, RuntimeError, ValueError) as exc:
            print(f"Error: correlation search failed: {exc}", file=sys.stderr)
            return 1
        print(json.dumps(result, indent=2))
        return 0

    # Vault search mode: query prior runs and exit (no input file required).
    if args.vault_search:
        matches = _vault_search(config, args.vault_search, args.vault_search_type)
        print(json.dumps({"query": args.vault_search, "matches": matches}, indent=2))
        return 0

    return None


def apply_runtime_config(args, config) -> None:
    """Apply offline override, analysis profiles, depth/artifact overrides, and
    set up logging. Runs after early-exit commands, before analysis."""
    # Hard offline override: disable all outbound enrichment regardless of config.
    config.set("plugin_offline", bool(args.offline))
    if args.offline:
        config.set("enable_geo_enrichment", False)
        config.set("enable_whois", False)
        # YARA is a purely local scan and stays available offline; only the
        # network-dependent enrichment providers are disabled here.

    # Extra plugin directories: merged into config so the engine's plugin
    # manager discovers them alongside the configured and default dirs.
    if args.plugin_dir:
        merged = list(config.get("plugin_dirs", []) or [])
        merged.extend(str(p) for p in args.plugin_dir if str(p) not in merged)
        config.set("plugin_dirs", merged)

    # Apply profile presets
    if args.analysis_profile == "safe":
        config.set("max_recursion_depth", 3)
        config.set("max_node_count", 50)
        config.set(
            "analysis_timeout_seconds",
            min(int(config.get("analysis_timeout_seconds", 300)), 60),
        )
        config.set(
            "decode_timeout_seconds",
            min(int(config.get("decode_timeout_seconds", 10)), 5),
        )
        config.set(
            "analyzer_timeout_seconds",
            min(int(config.get("analyzer_timeout_seconds", 10)), 5),
        )
    elif args.analysis_profile == "fast":
        config.set("max_recursion_depth", 3)
        config.set("max_node_count", 50)
    elif args.analysis_profile == "full":
        config.set("max_recursion_depth", 8)
        config.set("max_node_count", 200)

    # Override max depth if specified
    if args.max_depth is not None:
        config.set("max_recursion_depth", args.max_depth)

    # Override max artifacts
    if args.max_artifacts is not None:
        config.set("max_node_count", args.max_artifacts)

    # Setup secure logging with PII redaction
    if config.get("enable_logging", True):
        from .core.secure_logging import setup_secure_logging

        level = "DEBUG" if args.verbose else config.get("log_level", "INFO")
        setup_secure_logging(
            level,
            enable_redaction=args.enable_redaction,
            log_json=bool(args.log_json),
        )


def load_input(args, config) -> bytes:
    """Read the input payload, or empty bytes for evidence-only mode.

    Exits (SystemExit) with the appropriate code/message on a missing input
    source, unreadable/empty file — the same behavior main() had inline, now
    independently testable.
    """
    if not args.file:
        # Evidence-only mode: ingest IR logs/artifacts without a payload to
        # decode. With no input source at all, this is an error.
        if not args.evidence:
            print("Error: --file, --batch, or --evidence is required")
            sys.exit(1)
        return b""

    if not args.file.exists():
        print(f"Error: Input file {args.file} does not exist")
        sys.exit(1)

    # Read input data with error handling
    try:
        data = args.file.read_bytes()
    except PermissionError:
        print(f"Error: Permission denied reading {args.file}")
        sys.exit(1)
    except OSError as e:
        print(f"Error: Could not read file {args.file}: {e}")
        sys.exit(1)

    if len(data) == 0:
        print(f"Error: Input file {args.file} is empty")
        sys.exit(1)

    # Check file size
    max_size = config.get("max_data_size", 50 * 1024 * 1024)
    if len(data) > max_size:
        if not args.quiet:
            print(
                f"Warning: File size ({len(data)} bytes) exceeds max_data_size ({max_size} bytes)",
                file=sys.stderr,
            )
            print(
                "Analysis may be slow or incomplete. Increase max_data_size in config if needed.",
                file=sys.stderr,
            )
    return data


def parse_evidence_stage(args):
    """Parse optional IR evidence inputs, before the (long) analysis.

    A bad ``--evidence`` path fails fast (SystemExit) instead of wasting a
    completed run; other parse errors degrade to no evidence.
    """
    try:
        return _parse_evidence_specs(args.evidence)
    except SystemExit:
        raise
    except Exception as e:
        if args.verbose:
            print(f"Warning: failed to parse evidence inputs: {e}", file=sys.stderr)
        return None


def run_analysis_stage(args, config, data):
    """Initialize the engine and run analysis (with optional profiling and the
    offline network guard). Returns ``(report, engine)``."""
    try:
        engine = TitanEngine(config)
    except Exception as e:
        print(f"Error: Failed to initialize engine: {e}")
        sys.exit(1)

    if args.perf_profile:
        from .core.profiling import PerformanceProfiler

        profiler = PerformanceProfiler()

        if args.offline:
            with block_network():
                with profiler.profile(enable_cprofile=True) as metrics:
                    report = engine.run_analysis(data)
                    report.setdefault("meta", {})
                    report["meta"]["network_blocked"] = is_network_blocked()
        else:
            with profiler.profile(enable_cprofile=True) as metrics:
                report = engine.run_analysis(data)

        # Populate throughput metrics (execution_time is only final once the
        # profiling context has exited).
        metrics.operation_count = int(report.get("node_count") or 0)
        if metrics.execution_time > 0:
            metrics.throughput = metrics.operation_count / metrics.execution_time

        # Print profiling results
        print("\n" + "=" * 80)
        print("PERFORMANCE PROFILE RESULTS")
        print("=" * 80)
        mem_note = "" if profiler.process is not None else "  (psutil not installed)"
        print(f"Execution Time:    {metrics.execution_time:.4f} seconds")
        print(f"Memory Peak:       {metrics.memory_peak:.2f} MB{mem_note}")
        print(f"Memory Average:    {metrics.memory_average:.2f} MB{mem_note}")
        print(f"CPU Usage:         {metrics.cpu_percent:.2f}%{mem_note}")
        print(f"Nodes Processed:   {metrics.operation_count}")
        print(f"Throughput:        {metrics.throughput:.2f} nodes/sec")
        print(f"Function Calls:    {metrics.function_calls}")

        if metrics.top_functions:
            print("\nTop 10 Slowest Functions:")
            for i, (func, time_taken) in enumerate(
                sorted(metrics.top_functions.items(), key=lambda x: x[1], reverse=True)[
                    :10
                ],
                1,
            ):
                print(f"  {i:2d}. {func:<50} {time_taken:.4f}s")

        print("=" * 80 + "\n")

        if args.profile_out:
            # Save profile data
            profile_data = {
                "execution_time": metrics.execution_time,
                "memory_peak": metrics.memory_peak,
                "memory_average": metrics.memory_average,
                "cpu_percent": metrics.cpu_percent,
                "operation_count": metrics.operation_count,
                "throughput": metrics.throughput,
                "function_calls": metrics.function_calls,
                "top_functions": metrics.top_functions,
            }
            args.profile_out.write_text(json.dumps(profile_data, indent=2))
            print(f"Profile saved to {args.profile_out}")
    else:
        if args.progress and not args.quiet:
            print("Starting analysis...", file=sys.stderr)
        try:
            if args.offline:
                with block_network():
                    report = engine.run_analysis(data)
                    report.setdefault("meta", {})
                    report["meta"]["network_blocked"] = is_network_blocked()
            else:
                report = engine.run_analysis(data)
        except KeyboardInterrupt:
            print("\nAnalysis interrupted by user")
            sys.exit(130)
        except MemoryError:
            print("Error: Out of memory during analysis")
            print("Try reducing max_node_count or max_recursion_depth in config")
            sys.exit(1)
        except Exception as e:
            print(f"Error: Analysis failed: {e}")
            import traceback

            if args.verbose:
                traceback.print_exc()
            sys.exit(1)
        if args.progress and not args.quiet:
            print(
                f"Analysis complete: {report['node_count']} nodes generated",
                file=sys.stderr,
            )

    # Record run mode metadata for auditability.
    report.setdefault("meta", {})
    report["meta"]["offline"] = bool(args.offline)
    report["meta"]["enrichment_requested"] = bool(args.enable_enrichment)
    report["meta"].setdefault("network_blocked", bool(args.offline))
    if args.seed is not None:
        report["meta"]["seed"] = int(args.seed)

    return report, engine


def attach_evidence_stage(args, report, evidence_result) -> None:
    """Attach normalized IR evidence (events/indicators/links) to the report."""
    # Attach normalized evidence (parsed before the analysis above).
    if evidence_result is not None:
        # Deterministic ordering for stable reports.
        events_sorted = sorted(
            evidence_result.events,
            key=lambda ev: (
                ev.timestamp or "",
                ev.event_type or "",
                ev.source or "",
                ev.event_id or "",
            ),
        )
        indicators_sorted = sorted(
            evidence_result.indicators,
            key=lambda ind: (ind.indicator_type or "", ind.value or ""),
        )

        evidence_events = [e.to_dict() for e in events_sorted]
        evidence_indicators = [i.to_dict() for i in indicators_sorted]
        links = build_links_from_evidence_events(evidence_events)

        report["evidence"] = {
            "events": evidence_events,
            "indicators": evidence_indicators,
            "last_seen": build_last_seen(indicators_sorted),
            "top_pivots": top_pivots(indicators_sorted, limit=10),
            "entity_hints": build_entity_hints(indicators_sorted),
            "links": links,
            "top_links": top_links(links, limit=10),
        }


# Bounded plugin output: a plugin may contribute at most this many findings
# or report sections per run, mirroring the per-pack rule limit.
MAX_PLUGIN_FINDINGS = 200
MAX_PLUGIN_SECTIONS = 20
MAX_PLUGIN_EXTRACTIONS = 100


def _plugin_context(config, args):
    """Build the PluginContext SDK plugins receive from this run."""
    from .plugins import PluginContext

    return PluginContext(
        config=dict(getattr(config, "_config", {}) or {}),
        offline=bool(getattr(args, "offline", False)),
    )


def _run_detection_plugins(args, config, report, iocs, engine):
    """Run loaded detection plugins; return their findings as detection dicts.

    A failing plugin is skipped with a warning — plugins must never be able
    to abort an analysis. Findings under undeclared rule IDs are dropped
    (the declared set was validated at load time, including the reserved
    ``TITAN-`` prefix and cross-plugin uniqueness).
    """
    manager = getattr(engine, "plugin_manager", None)
    if manager is None or not getattr(manager, "detections", None):
        return []

    context = _plugin_context(config, args)
    results = []
    for plugin in manager.get_detections():
        declared = {str(rule_id) for rule_id in plugin.rule_ids}
        try:
            findings = list(plugin.detect(report, iocs, context))
        except Exception as exc:
            if not args.quiet:
                print(
                    f"Warning: detection plugin {plugin.name} failed: {exc}",
                    file=sys.stderr,
                )
            continue
        for finding in findings[:MAX_PLUGIN_FINDINGS]:
            data = finding.to_dict() if hasattr(finding, "to_dict") else None
            if not isinstance(data, dict) or data.get("rule_id") not in declared:
                if not args.quiet:
                    print(
                        f"Warning: detection plugin {plugin.name} emitted an "
                        "invalid or undeclared finding; dropped",
                        file=sys.stderr,
                    )
                continue
            data["source"] = {"type": "plugin", "plugin": str(plugin.name)}
            results.append(data)
    return results


def run_config_extractors_stage(args, config, report, engine) -> None:
    """Run isolated config extractors over every artifact-graph payload."""
    manager = getattr(engine, "plugin_manager", None)
    if manager is None or not getattr(manager, "extractors", None):
        return

    context = _plugin_context(config, args)
    results: list[dict[str, Any]] = []
    for plugin in manager.get_extractors():
        for node_id, payload in engine.artifact_payloads():
            if len(results) >= MAX_PLUGIN_EXTRACTIONS:
                break
            try:
                if not plugin.can_extract(payload, context):
                    continue
                extracted = list(plugin.extract(payload, context))
            except Exception as exc:
                if not args.quiet:
                    print(
                        f"Warning: config extractor {plugin.name} failed: {exc}",
                        file=sys.stderr,
                    )
                continue
            for value in extracted[:MAX_PLUGIN_EXTRACTIONS]:
                data = value.to_dict() if hasattr(value, "to_dict") else None
                if not isinstance(data, dict):
                    continue
                data["node_id"] = int(node_id)
                data["plugin"] = str(plugin.name)
                try:
                    json.dumps(data)
                except (TypeError, ValueError):
                    continue
                results.append(data)
                if len(results) >= MAX_PLUGIN_EXTRACTIONS:
                    break
    if results:
        results.sort(
            key=lambda item: (
                item.get("family", ""),
                item.get("node_id", -1),
                item.get("plugin", ""),
            )
        )
        report["config_extractions"] = results


def _run_yara_stage(args, config, report, detections, engine):
    """Scan every artifact-graph node with configured YARA rules.

    ``--yara-rules`` sources are merged into the configured file/directory
    lists and imply enabling YARA for the run. The full bounded scan result
    is persisted as ``report["yara"]``, and matches are appended to
    ``detections`` (one entry per distinct rule, carrying all matched node
    ids) so they feed risk scoring and intelligence like any other rule.
    Returns the raw match list for the risk engine's YARA weighting.
    """
    from .core.yara_scanner import YaraScanner, yara_matches_to_detections

    cli_sources = list(getattr(args, "yara_rules", None) or [])
    if cli_sources:
        files = list(config.get("yara_rules_files", []) or [])
        dirs = list(config.get("yara_rules_dirs", []) or [])
        for source in cli_sources:
            source = Path(source)
            if source.is_dir():
                dirs.append(str(source))
            else:
                files.append(str(source))
        config.set("yara_rules_files", files)
        config.set("yara_rules_dirs", dirs)
        config.set("enable_yara", True)
    if not config.get("enable_yara", False):
        return None

    scanner = YaraScanner(config._config)
    payloads = engine.artifact_payloads() if engine is not None else []
    result = scanner.scan(payloads)
    report["yara"] = result
    detections.extend(yara_matches_to_detections(result))
    if result.get("state") != "completed":
        import logging

        logging.getLogger(__name__).warning(
            "YARA scanning was requested but did not run: %s",
            result.get("reason") or result.get("state"),
        )
    return result.get("matches") or None


def run_detections_stage(args, config, report, evidence_result, engine=None):
    """Run detection rules, detection plugins, and risk scoring if requested.

    Returns ``(detections, risk_assessment)`` and persists both into the
    report. Detection plugins (loaded by the engine's plugin manager) run
    after the rule engines and before risk scoring, so plugin findings feed
    the risk assessment exactly like rule matches.
    """
    # Run detections and risk scoring if requested
    detections = []
    risk_assessment = None
    if args.enable_detections:
        if args.progress and not args.quiet:
            print("Running detection rules...", file=sys.stderr)
        from .core.detection_rules import CorrelationRulesEngine
        from .core.risk_scoring import RiskScoringEngine
        from .core.ioc_export import build_ioc_summary

        pack_paths = []
        try:
            pack_paths.extend(config.get("detection_rule_packs", []) or [])
        except Exception:
            pass
        if args.rules_pack:
            pack_paths.extend(args.rules_pack)

        if args.rules_pack_dir:
            for d in args.rules_pack_dir:
                d = Path(d)
                if d.exists() and d.is_dir():
                    for ext in ("*.json", "*.yml", "*.yaml"):
                        pack_paths.extend(sorted(d.glob(ext)))

        rules_engine = CorrelationRulesEngine([Path(p) for p in pack_paths])
        iocs = build_ioc_summary(report, None)
        _merge_evidence_iocs(iocs, evidence_result)
        detections = rules_engine.evaluate_all(report, iocs)
        detections.extend(_run_detection_plugins(args, config, report, iocs, engine))

        if getattr(rules_engine, "rule_packs", None) is not None:
            report.setdefault("meta", {})
            report["meta"]["rule_packs"] = rules_engine.rule_packs

        yara_matches = _run_yara_stage(args, config, report, detections, engine)

        risk_engine = RiskScoringEngine()
        risk_assessment = risk_engine.compute_risk_score(
            report, iocs, detections, yara_matches=yara_matches
        )

        # Persist these in the report for downstream tooling.
        report["detections"] = detections
        report["risk_assessment"] = risk_assessment

        if args.progress and not args.quiet:
            print(f"Detections: {len(detections)} rules triggered", file=sys.stderr)
            print(
                f"Risk Level: {risk_assessment['risk_level']} (Score: {risk_assessment['risk_score']}/100)",
                file=sys.stderr,
            )

    return detections, risk_assessment


def attach_intelligence_stage(
    args, report, detections, risk_assessment, evidence_result
) -> None:
    """Attach deterministic analyst-oriented intelligence to every report.

    IOCs are rebuilt with the same summary+evidence merge used by the
    detection stage and case reports, so intelligence network signals stay
    consistent with the indicators quoted elsewhere in the outputs.
    """
    from .core.intelligence import IntelligenceEngine
    from .core.ioc_export import build_ioc_summary

    iocs = build_ioc_summary(report, None)
    _merge_evidence_iocs(iocs, evidence_result)

    engine = IntelligenceEngine()
    report["intelligence"] = engine.analyze(
        report,
        iocs=iocs,
        detections=detections,
        risk=risk_assessment,
    )


def attach_assurance_stage(
    config,
    report,
    titan_engine=None,
    evidence_result=None,
    source_path: Path | None = None,
    *,
    allow_external_providers: bool = False,
) -> None:
    """Run offline static controls and attach a fail-closed assurance verdict."""
    if not config.get("enable_assurance", True):
        return
    from .core.assurance import AssuranceEngine
    from .core.ioc_export import build_ioc_summary

    engine = AssuranceEngine(config._config)
    if source_path is not None:
        from .core.assurance_providers import AssuranceProviderRunner

        AssuranceProviderRunner(config._config).collect(
            source_path,
            report,
            allow_external=allow_external_providers,
        )
    artifacts = titan_engine.artifact_payloads() if titan_engine is not None else None
    iocs = build_ioc_summary(report, None)
    _merge_evidence_iocs(iocs, evidence_result)
    engine.run_static_checks(report, artifacts, iocs=iocs)
    report["assurance"] = engine.evaluate(report)


def attach_threat_intelligence_stage(args, report, detections, evidence_result) -> None:
    """Attach deterministic ATT&CK, LOLBin, and behavioral mappings."""
    from .core.ioc_export import build_ioc_summary
    from .threat_intel import ThreatIntelligenceEngine

    iocs = build_ioc_summary(report, None)
    _merge_evidence_iocs(iocs, evidence_result)
    report["threat_intelligence"] = ThreatIntelligenceEngine().analyze(
        report,
        iocs=iocs,
        detections=detections,
    )


def run_enrichment_stage(args, config, report, evidence_result) -> None:
    """Optionally enrich IOCs (explicit opt-in; blocked by --offline)."""
    # Optional enrichment (explicit opt-in; blocked by --offline)
    if args.enable_enrichment and not args.offline:
        if args.progress and not args.quiet:
            print("Enriching IOCs...", file=sys.stderr)
        from .core.enrichment import EnrichmentEngine
        from .core.ioc_export import build_ioc_summary

        if getattr(args, "enrichment_cache_path", None):
            config.set("enrichment_cache_path", str(args.enrichment_cache_path))
        if getattr(args, "refresh_enrichment", False):
            config.set("refresh_enrichment", True)

        enrichment_engine = EnrichmentEngine(config._config)
        iocs = build_ioc_summary(report, None)
        _merge_evidence_iocs(iocs, evidence_result)
        report["enrichment"] = enrichment_engine.enrich_iocs(iocs)
        report.setdefault("meta", {})
        try:
            report["meta"]["enrichment_cache"] = enrichment_engine.cache_info()
        except Exception:
            pass
        # Report providers that actually initialized (library present, DB/rules
        # loaded), not merely what the config asked for.
        report["meta"]["enrichment_providers"] = enrichment_engine.active_providers()
        enrichment_engine.cleanup()

        if args.progress and not args.quiet:
            print("Enrichment complete", file=sys.stderr)
    elif args.enable_enrichment and args.offline:
        report["meta"]["enrichment_providers"] = []
        if not args.quiet:
            print(
                "Offline mode enabled: skipping enrichment.",
                file=sys.stderr,
            )


def run_phase5_correlation_stage(args, report) -> int:
    """Run Phase 5 cross-case correlation when any of its outputs were requested.

    Embeds the correlation sections into the report and writes any requested
    per-section JSON files plus the analyst view. Returns 0 on success (or
    when Phase 5 was not requested) and 1 on failure.
    """
    requested = any(
        (
            args.correlation_db,
            args.correlation_out,
            args.campaign_out,
            args.timeline_correlation_out,
            args.infrastructure_reuse_out,
            args.shared_payload_out,
            args.attribution_hints_out,
            args.analyst_correlation_out,
        )
    )
    if not requested:
        return 0

    try:
        from .correlation.service import analyze_milestone5
        from .correlation.views import to_html as phase5_to_html
        from .correlation.views import to_markdown as phase5_to_markdown

        db_path = args.correlation_db or (
            Path.home() / ".titan_decoder" / "correlation.sqlite3"
        )
        phase5 = analyze_milestone5(
            report,
            db_path,
            minimum_relationship_score=float(args.correlation_min_score),
            minimum_campaign_score=float(args.campaign_min_score),
            minimum_payload_score=float(args.shared_payload_min_score),
            timeline_window_seconds=float(args.timeline_window_seconds),
            record_subject=not args.correlation_no_record,
        )
        for key in (
            "correlation",
            "campaigns",
            "timeline_correlation",
            "infrastructure_reuse",
            "shared_payloads",
            "attribution_hints",
        ):
            report[key] = phase5[key]

        section_outputs = (
            (args.correlation_out, phase5["correlation"]),
            (args.campaign_out, phase5["campaigns"]),
            (args.timeline_correlation_out, phase5["timeline_correlation"]),
            (args.infrastructure_reuse_out, phase5["infrastructure_reuse"]),
            (args.shared_payload_out, phase5["shared_payloads"]),
            (args.attribution_hints_out, phase5["attribution_hints"]),
        )
        for path, payload in section_outputs:
            if path:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

        if args.analyst_correlation_out:
            view = phase5["analyst_view"]
            if args.analyst_correlation_format == "html":
                rendered = phase5_to_html(view)
            elif args.analyst_correlation_format == "markdown":
                rendered = phase5_to_markdown(view)
            else:
                rendered = json.dumps(view, indent=2)
            args.analyst_correlation_out.parent.mkdir(parents=True, exist_ok=True)
            args.analyst_correlation_out.write_text(rendered, encoding="utf-8")

        if not args.quiet:
            print(
                f"Phase 5 correlation complete (database: {db_path})",
                file=sys.stderr,
            )
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"Error: Phase 5 correlation failed: {exc}", file=sys.stderr)
        return 1
    return 0


def _run_report_plugins(args, config, report, engine) -> None:
    """Collect sections from report plugins into ``report["plugin_report_sections"]``.

    Sections must be JSON-serializable and are bounded per plugin. A failing
    plugin is skipped with a warning; plugins can extend reports but never
    break them.
    """
    manager = getattr(engine, "plugin_manager", None)
    if manager is None or not getattr(manager, "reports", None):
        return

    from .plugins import ReportSection

    context = _plugin_context(config, args)
    sections = []
    for plugin in manager.get_reports():
        try:
            built = list(plugin.build_sections(report, context))
        except Exception as exc:
            if not args.quiet:
                print(
                    f"Warning: report plugin {plugin.name} failed: {exc}",
                    file=sys.stderr,
                )
            continue
        for section in built[:MAX_PLUGIN_SECTIONS]:
            if not isinstance(section, ReportSection):
                continue
            data = section.to_dict()
            data["plugin"] = str(plugin.name)
            try:
                json.dumps(data)
            except (TypeError, ValueError):
                if not args.quiet:
                    print(
                        f"Warning: report plugin {plugin.name} section "
                        f"{section.section_id} is not JSON-serializable; dropped",
                        file=sys.stderr,
                    )
                continue
            sections.append(data)
    if sections:
        sections.sort(
            key=lambda item: (item.get("order", 100), item.get("section_id", ""))
        )
        report["plugin_report_sections"] = sections


def write_outputs_stage(
    args, config, report, engine, detections, risk_assessment, evidence_result
) -> int:
    """Run all exports, contract validation, output, and compute the exit code.

    Covers forensics, IOC/case-report/correlation, timeline, graph, JSONL,
    vault, strict validation, the report-size guard, stdout/file output, and the
    ``--fail-on-risk-level`` exit code. Returns the process exit code.
    """
    # Phase 5 cross-case correlation (runs first so its sections are embedded
    # in the report before validation and stdout/file output).
    phase5_exit = run_phase5_correlation_stage(args, report)
    if phase5_exit != 0:
        return phase5_exit

    # Report plugins contribute analyst sections; embedded in the JSON report
    # and rendered into Markdown/HTML case reports.
    _run_report_plugins(args, config, report, engine)

    # Optional forensic attribution summary
    forensics_summary = None
    if args.forensics_out or args.forensics_print:
        forensics = ForensicsEngine()
        forensics_summary = forensics.analyze(report)

    # Optional IOC export / case report / correlation
    if args.ioc_out or args.report_out:
        from .core.ioc_export import build_ioc_summary, export_iocs
        from .core.case_report import build_case_report, to_markdown, to_html

        iocs = build_ioc_summary(report, forensics_summary)
        _merge_evidence_iocs(iocs, evidence_result)

        # Correlation (optional, config-driven). Deprecated: the Phase 5
        # correlation database (--correlation-db and friends) supersedes this
        # store with evidence-backed relationships and cross-case search.
        if config.get("enable_correlation", False):
            if not args.quiet:
                print(
                    "Warning: enable_correlation/CorrelationStore is deprecated; "
                    "use --correlation-db and --correlation-search instead.",
                    file=sys.stderr,
                )
            try:
                from .core.correlation import CorrelationStore

                # Config values arrive as plain strings from JSON; a str has no
                # .parent, which used to raise here and silently disable
                # correlation for any user-configured db path.
                db_path = Path(
                    config.get("correlation_db_path")
                    or (Path.home() / ".titan_decoder" / "correlation.db")
                )
                db_path.parent.mkdir(parents=True, exist_ok=True)
                with CorrelationStore(db_path) as store:
                    analysis_id = (
                        report.get("meta", {}).get("analysis_id") or "analysis"
                    )
                    # Correlate against *prior* runs before recording this one,
                    # otherwise every IOC trivially matches the current run.
                    matches = store.correlate(iocs)
                    store.record_analysis(analysis_id, iocs)
                    if matches:
                        if not forensics_summary:
                            forensics_summary = {}
                        forensics_summary["correlation_matches"] = matches
            except Exception as e:
                # Surface the failure: silently dropping correlation hid a bug
                # where any configured db path crashed this block.
                if not args.quiet:
                    print(
                        f"Warning: correlation disabled due to error: {e}",
                        file=sys.stderr,
                    )

        if args.ioc_out:
            export_iocs(iocs, args.ioc_out, args.ioc_format)
            if not args.quiet:
                print(
                    f"IOCs exported to {args.ioc_out} ({args.ioc_format})",
                    file=sys.stderr,
                )

        if args.report_out:
            case = build_case_report(report, forensics_summary, iocs)
            if args.report_format == "html":
                args.report_out.write_text(to_html(case), encoding="utf-8")
            else:
                args.report_out.write_text(to_markdown(case), encoding="utf-8")
            if not args.quiet:
                print(
                    f"Case report saved to {args.report_out} ({args.report_format})",
                    file=sys.stderr,
                )

    # Timeline export
    if args.timeline_out:
        from .core.timeline import build_timeline, export_timeline

        timeline = build_timeline(report)
        export_timeline(timeline, args.timeline_out, args.timeline_format)
        if not args.quiet:
            print(
                f"Timeline exported to {args.timeline_out} ({args.timeline_format})",
                file=sys.stderr,
            )

    # Evidence timeline export (from evidence events)
    if args.evidence_timeline_out:
        from .core.evidence_timeline import (
            build_evidence_timeline,
            export_evidence_timeline,
        )

        ev_tl = build_evidence_timeline(report)
        export_evidence_timeline(
            ev_tl, args.evidence_timeline_out, args.evidence_timeline_format
        )
        if not args.quiet:
            print(
                f"Evidence timeline exported to {args.evidence_timeline_out} ({args.evidence_timeline_format})",
                file=sys.stderr,
            )

    # Export graph if requested. Use the completed report so the exporter can
    # add Intelligence metadata without coupling interpretation into TitanEngine.
    if args.graph:
        try:
            from .core.graph_export import GraphExporter

            graph_exporter = GraphExporter(
                report.get("nodes") or [],
                intelligence=report.get("intelligence") or {},
                threat_intelligence=report.get("threat_intelligence") or {},
            )
            if args.graph_format == "dot":
                graph_exporter.save_dot(args.graph)
            elif args.graph_format == "mermaid":
                graph_exporter.save_mermaid(args.graph)
            else:
                graph_exporter.save_json(args.graph)
            if not args.quiet:
                print(
                    f"Graph exported to {args.graph} (format: {args.graph_format})",
                    file=sys.stderr,
                )
        except PermissionError:
            print(f"Error: Permission denied writing to {args.graph}")
        except OSError as e:
            print(f"Error: Could not write graph file: {e}")
        except Exception as e:
            print(f"Error exporting graph: {e}")
            if args.verbose:
                import traceback

                traceback.print_exc()

    # JSONL export (pipeline-friendly)
    if args.jsonl_out:
        _write_jsonl(report, args.jsonl_out)

    # Vault storage (history/search)
    if args.vault_store:
        _vault_store(config, report)

    # Strict validation (contract enforcement)
    if bool(config.get("strict", False)):
        ok, errors = _validate_report_contract(report)
        if not ok:
            if not args.quiet:
                print(
                    json.dumps({"ok": False, "errors": errors}, indent=2),
                    file=sys.stderr,
                )
            sys.exit(1)

    # Optional human-readable intelligence output. It goes to stderr so
    # JSON stdout remains machine-readable and backward compatible.
    if args.explain:
        from .core.explain import generate_explanation

        print("\n" + generate_explanation(report) + "\n", file=sys.stderr)

    if args.intelligence_out:
        intelligence_json = json.dumps(report.get("intelligence") or {}, indent=2)
        try:
            args.intelligence_out.write_text(intelligence_json)
            if not args.quiet:
                print(
                    f"Intelligence summary saved to {args.intelligence_out}",
                    file=sys.stderr,
                )
        except PermissionError:
            print(
                f"Error: Permission denied writing to {args.intelligence_out}",
                file=sys.stderr,
            )
            sys.exit(1)
        except OSError as e:
            print(
                f"Error: Could not write intelligence file: {e}",
                file=sys.stderr,
            )
            sys.exit(1)

    # Pre-serialize report once (used for stdout + file + size guard)
    report_json = json.dumps(report, indent=2)

    # Report size guard (optional)
    max_mb = config.get("max_report_size_mb")
    if max_mb is not None:
        max_bytes = int(float(max_mb) * 1024 * 1024)
        if len(report_json.encode("utf-8")) > max_bytes:
            print(
                f"Error: Report exceeds max-report-size-mb ({max_mb} MB)",
                file=sys.stderr,
            )
            sys.exit(1)

    # Output results with error handling
    if args.out:
        try:
            args.out.write_text(report_json)
            if not args.quiet:
                print(f"Report saved to {args.out}", file=sys.stderr)
        except PermissionError:
            print(f"Error: Permission denied writing to {args.out}")
            sys.exit(1)
        except OSError as e:
            print(f"Error: Could not write report file: {e}")
            sys.exit(1)
    else:
        try:
            if args.stdout == "json":
                print(report_json)
        except BrokenPipeError:
            # Handle pipe closed (e.g., piping to head)
            pass

    if forensics_summary:
        if args.forensics_out:
            args.forensics_out.write_text(json.dumps(forensics_summary, indent=2))
            if not args.quiet:
                print(
                    f"Forensics summary saved to {args.forensics_out}",
                    file=sys.stderr,
                )
        if args.forensics_print:
            print("\nFORENSICS SUMMARY:\n" + json.dumps(forensics_summary, indent=2))

    # Optional CI/pipeline behavior: fail based on risk level.
    exit_code = 0
    if args.fail_on_risk_level:
        if not risk_assessment:
            print(
                "Warning: --fail-on-risk-level set but no risk_assessment present. "
                "Run with --enable-detections.",
                file=sys.stderr,
            )
        else:
            ordering = ["CLEAN", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
            current = risk_assessment.get("risk_level", "CLEAN")
            try:
                if ordering.index(current) >= ordering.index(args.fail_on_risk_level):
                    exit_code = 2
                    print(
                        f"Failing due to risk level {current} (threshold: {args.fail_on_risk_level})",
                        file=sys.stderr,
                    )
            except ValueError:
                # Unknown risk level: don't fail silently; treat as suspicious.
                exit_code = 2
                print(
                    f"Failing due to unrecognized risk level: {current}",
                    file=sys.stderr,
                )

    # Summary footer
    if not args.quiet:
        print("\n" + "=" * 80, file=sys.stderr)
        print(
            f"TITAN ENGINE ANALYSIS COMPLETE — v{report['meta']['version']}",
            file=sys.stderr,
        )
        print("=" * 80, file=sys.stderr)
        print(f"Nodes Generated:   {report['node_count']}", file=sys.stderr)
        print(
            f"IOCs Found:        {sum(len(v) for v in report.get('iocs', {}).values())}",
            file=sys.stderr,
        )
        if detections:
            print(
                f"Detections:        {len(detections)} rules triggered",
                file=sys.stderr,
            )
        if risk_assessment:
            print(
                f"Risk Level:        {risk_assessment['risk_level']} (Score: {risk_assessment['risk_score']}/100)",
                file=sys.stderr,
            )
            if risk_assessment.get("top_reasons"):
                print(
                    f"Top Risk Factors:  {', '.join(risk_assessment['top_reasons'][:3])}",
                    file=sys.stderr,
                )
        assurance = report.get("assurance") or {}
        if assurance:
            print(
                "Assurance Verdict: "
                f"{assurance.get('verdict', 'INDETERMINATE')} "
                f"({assurance.get('controls_satisfied', 0)}/"
                f"{assurance.get('controls_total', 6)} controls)",
                file=sys.stderr,
            )
        print("=" * 80, file=sys.stderr)

    return exit_code


def run_deep_scan(args, config) -> int:
    """Run the recursive static scanner and optional recoverable quarantine."""
    from .core.deep_scan import DeepScanner
    from .core.quarantine import QuarantineVault

    configured = args.quarantine_dir or config.get("quarantine_dir")
    verdicts = {str(value).upper() for value in (args.quarantine_verdict or [])}
    vault = (
        QuarantineVault(Path(str(configured)) if configured else None)
        if verdicts
        else None
    )

    def progress(event: dict) -> None:
        if args.progress and not args.quiet:
            current = event.get("current", 0)
            total = event.get("total", 0)
            print(
                f"[{current}/{total}] {event.get('message', 'Scanning')}",
                file=sys.stderr,
            )

    try:
        summary = DeepScanner(
            config,
            progress_callback=progress,
            offline=bool(args.offline),
            supervised=bool(getattr(args, "deep_scan_supervised", False)),
        ).scan(
            args.deep_scan,
            pattern=args.deep_scan_pattern,
            reports_dir=args.deep_scan_reports,
            quarantine=vault,
            quarantine_verdicts=verdicts,
            quarantine_move=args.quarantine_action == "move",
            allow_external_providers=not args.offline,
        )
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"Error: deep scan failed: {exc}", file=sys.stderr)
        return 1

    encoded = json.dumps(summary, indent=2, sort_keys=True)
    if args.deep_scan_out:
        args.deep_scan_out.parent.mkdir(parents=True, exist_ok=True)
        args.deep_scan_out.write_text(encoded + "\n", encoding="utf-8")
    if args.stdout == "json":
        print(encoded)
    if getattr(args, "deep_scan_supervised", False) and (
        summary.get("error_count")
        or summary.get("cancelled")
        or summary.get("candidate_limit_reached")
    ):
        return 1
    return 0 if summary.get("analyzed_count", 0) else 1


def main():
    """Thin dispatcher: parse args, then drive the analysis stages.

    Each stage below is an independently callable, unit-testable function; this
    function only wires them together and translates the final exit code into a
    process exit. Keeping the orchestration flat here (rather than one ~900-line
    body) is what makes the CLI behaviors — batch handling, exit codes,
    evidence-before-analysis ordering — testable at the stage level.
    """
    args = build_parser().parse_args()
    if args.deep_scan_supervised and not args.deep_scan:
        build_parser().error("--deep-scan-supervised requires --deep-scan")

    # Interactive UI: hand off to the menu-driven front end and exit. Kept as an
    # early branch so none of the analysis-oriented argument validation runs.
    if args.interactive:
        from .interactive import main as interactive_main

        sys.exit(interactive_main())

    # Note: no custom SIGINT handler here. Python's default KeyboardInterrupt is
    # the abort mechanism (caught around the analysis calls); a custom handler
    # that merely sets a flag would swallow Ctrl+C without stopping anything.
    config = Config(args.config) if args.config else Config()
    apply_cli_config(args, config)

    # Early-exit informational / vault subcommands.
    rc = handle_info_commands(args, config)
    if rc is not None:
        sys.exit(rc)

    apply_runtime_config(args, config)

    if args.deep_scan:
        sys.exit(run_deep_scan(args, config))

    # Batch mode (sys.exit so the status code survives `python -m` invocation,
    # not just the console-script wrapper).
    if args.batch:
        sys.exit(run_batch_analysis(args, config))

    # Evidence parsed before the (potentially long) analysis so a bad path fails
    # fast instead of wasting a completed run.
    data = load_input(args, config)
    evidence_result = parse_evidence_stage(args)

    report, engine = run_analysis_stage(args, config, data)
    attach_evidence_stage(args, report, evidence_result)
    run_config_extractors_stage(args, config, report, engine)
    detections, risk_assessment = run_detections_stage(
        args, config, report, evidence_result, engine=engine
    )
    attach_assurance_stage(
        config,
        report,
        engine,
        evidence_result,
        args.file,
        allow_external_providers=not args.offline,
    )
    detections = report.get("detections") or detections
    risk_assessment = report.get("risk_assessment") or risk_assessment
    attach_intelligence_stage(
        args, report, detections, risk_assessment, evidence_result
    )
    attach_threat_intelligence_stage(args, report, detections, evidence_result)
    run_enrichment_stage(args, config, report, evidence_result)
    exit_code = write_outputs_stage(
        args, config, report, engine, detections, risk_assessment, evidence_result
    )
    sys.exit(exit_code)


def _merge_evidence_iocs(iocs: dict, evidence_result) -> None:
    """Merge evidence indicators into an IOC summary dict, in place."""
    if evidence_result is None:
        return
    for ind in evidence_result.indicators:
        key = ind.indicator_type
        if not key:
            continue
        iocs.setdefault(key, [])
        if ind.value not in iocs[key]:
            iocs[key].append(ind.value)
    for k in list(iocs.keys()):
        try:
            iocs[k] = sorted(set(iocs[k]))
        except Exception:
            pass


def _run_doctor(config: Config) -> dict:
    import platform
    import sys

    def has(mod: str) -> bool:
        try:
            __import__(mod)
            return True
        except Exception:
            return False

    pack_results = []
    for p in config.get("detection_rule_packs", []) or []:
        try:
            from titan_decoder.core.rule_packs import load_rule_pack

            info, rules = load_rule_pack(Path(p))
            pack_results.append(
                {
                    "path": str(p),
                    "ok": True,
                    "name": info.name,
                    "version": info.version,
                    "rule_count": len(rules),
                }
            )
        except Exception as e:
            pack_results.append({"path": str(p), "ok": False, "error": str(e)})

    format_status = optional_format_status()
    diag: dict[str, Any] = {
        "ok": True,
        "status": "ready" if format_status["ready"] else "degraded",
        "python": sys.version.split(" ")[0],
        "platform": platform.platform(),
        "version": TITAN_VERSION,
        "optional_dependencies": {
            "psutil": has("psutil"),
            "geoip2": has("geoip2"),
            "whois": has("whois"),
            "yara": has("yara"),
            "yaml": has("yaml"),
            "requests": has("requests"),
            **format_status["modules"],
        },
        "optional_formats": format_status,
        "warnings": (
            []
            if format_status["ready"]
            else [
                "Optional format support is incomplete; install the formats extra "
                "to enable Brotli, Zstandard, 7z, RAR, ISO, and CAB handling."
            ]
        ),
        "rule_packs": pack_results,
    }

    try:
        from titan_decoder.core.engine import SCHEMA_VERSION

        diag["schema_version"] = SCHEMA_VERSION
    except Exception:
        diag["schema_version"] = None

    if any((not r.get("ok")) for r in pack_results):
        diag["ok"] = False

    return diag


def _write_jsonl(report: dict, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)

    def emit(handle, event_type: str, payload: dict):
        handle.write(json.dumps({"type": event_type, **payload}) + "\n")

    with path.open("w") as handle:
        emit(handle, "meta", {"meta": report.get("meta", {})})
        emit(handle, "run_manifest", {"run_manifest": report.get("run_manifest", {})})
        for node in report.get("nodes", []) or []:
            emit(handle, "node", {"node": node})
        for det in report.get("detections", []) or []:
            emit(handle, "detection", {"detection": det})
        if report.get("risk_assessment"):
            emit(handle, "risk", {"risk_assessment": report.get("risk_assessment")})
        emit(handle, "iocs", {"iocs": report.get("iocs", {})})


def _vault_paths(config: Config) -> tuple[Path, Path]:
    vault_dir = config.get("vault_dir")
    vault_dir = (
        Path(vault_dir) if vault_dir else (Path.home() / ".titan_decoder" / "vault")
    )

    db_path = config.get("vault_db_path")
    db_path = Path(db_path) if db_path else (vault_dir / "vault.db")
    return vault_dir, db_path


def _vault_store(config: Config, report: dict) -> None:
    from titan_decoder.core.vault import VaultStore, VaultError

    vault_dir, db_path = _vault_paths(config)
    vault_dir.mkdir(parents=True, exist_ok=True)

    analysis_id = report.get("meta", {}).get("analysis_id") or "analysis"
    report_path = vault_dir / f"{analysis_id}.json"
    report_path.write_text(json.dumps(report, indent=2))

    node_count = int(report.get("node_count") or 0)
    risk = report.get("risk_assessment") or {}
    risk_level = risk.get("risk_level")
    risk_score = risk.get("risk_score")
    iocs = report.get("iocs", {}) or {}
    ioc_count = sum(len(v) for v in iocs.values() if isinstance(v, list))

    # The report JSON is already persisted above; if the index DB is corrupt,
    # warn but don't crash (and don't lose the completed analysis).
    try:
        with VaultStore(db_path) as store:
            store.record_run(
                analysis_id,
                report_path,
                node_count=node_count,
                risk_level=str(risk_level) if risk_level is not None else None,
                risk_score=int(risk_score)
                if isinstance(risk_score, (int, float))
                else None,
                ioc_count=int(ioc_count),
            )
            store.record_iocs(analysis_id, iocs)
    except VaultError as e:
        print(f"Warning: vault indexing skipped: {e}", file=sys.stderr)


def _vault_search(config: Config, value: str, ioc_type: str | None = None) -> list:
    from titan_decoder.core.vault import VaultStore, VaultError

    _, db_path = _vault_paths(config)
    if not db_path.exists():
        return []
    try:
        with VaultStore(db_path) as store:
            return store.search_value(value, ioc_type=ioc_type)
    except VaultError as e:
        print(f"Warning: {e}", file=sys.stderr)
        return []


def _vault_list_recent(config: Config, limit: int) -> list:
    from titan_decoder.core.vault import VaultStore, VaultError

    _, db_path = _vault_paths(config)
    if not db_path.exists():
        return []
    try:
        with VaultStore(db_path) as store:
            return store.list_recent(limit=limit)
    except VaultError as e:
        print(f"Warning: {e}", file=sys.stderr)
        return []


def _vault_prune(config: Config, days: int) -> dict:
    from titan_decoder.core.vault import VaultStore, VaultError

    _, db_path = _vault_paths(config)
    if not db_path.exists():
        return {
            "ok": True,
            "result": {"before_runs": 0, "after_runs": 0, "deleted_runs": 0},
        }
    try:
        with VaultStore(db_path) as store:
            result = store.prune_days(days)
    except VaultError as e:
        return {"ok": False, "error": str(e)}
    return {"ok": True, "result": result}


def _validate_report_contract(report: dict) -> tuple[bool, list[str]]:
    errors: list[str] = []
    if not isinstance(report, dict):
        return False, ["Report is not an object"]

    meta = report.get("meta")
    if not isinstance(meta, dict):
        errors.append("meta missing or not an object")
    else:
        for k in ("tool", "version", "schema_version", "analysis_id"):
            if k not in meta:
                errors.append(f"meta.{k} missing")

    if not isinstance(report.get("nodes"), list):
        errors.append("nodes missing or not an array")
    if not isinstance(report.get("iocs"), dict):
        errors.append("iocs missing or not an object")
    if "node_count" not in report:
        errors.append("node_count missing")

    try:
        from titan_decoder.core.engine import SCHEMA_VERSION

        if isinstance(meta, dict) and meta.get("schema_version") != SCHEMA_VERSION:
            errors.append(
                f"meta.schema_version mismatch (got {meta.get('schema_version')}, expected {SCHEMA_VERSION})"
            )
    except Exception:
        pass

    return (len(errors) == 0), errors


def run_batch_analysis(args, config):
    """Run analysis on multiple files in batch mode."""
    if not args.batch.exists() or not args.batch.is_dir():
        print(
            f"Error: Batch directory {args.batch} does not exist or is not a directory"
        )
        sys.exit(1)

    # Find all matching files (sorted for deterministic processing order).
    files = sorted(f for f in args.batch.glob(args.batch_pattern) if f.is_file())

    if not files:
        print(f"No files found matching pattern '{args.batch_pattern}' in {args.batch}")
        sys.exit(1)

    if not getattr(args, "quiet", False):
        print(f"Found {len(files)} files to analyze")

    # Batch mode only produces per-file JSON reports (plus optional vault
    # storage). Warn instead of silently ignoring single-file-only options.
    ignored = [
        name
        for name, flag in (
            ("--enable-detections", args.enable_detections),
            ("--enable-enrichment", args.enable_enrichment),
            ("--evidence", args.evidence),
            ("--ioc-out", args.ioc_out),
            ("--report-out", args.report_out),
            ("--graph", args.graph),
            ("--jsonl-out", args.jsonl_out),
            ("--timeline-out", args.timeline_out),
            ("--evidence-timeline-out", args.evidence_timeline_out),
            ("--forensics-out", args.forensics_out),
        )
        if flag
    ]
    if ignored:
        print(
            f"Warning: batch mode ignores: {', '.join(ignored)}",
            file=sys.stderr,
        )

    # Create output directory if needed
    if args.out:
        output_dir = args.out
        output_dir.mkdir(parents=True, exist_ok=True)
    else:
        output_dir = args.batch / "reports"
        output_dir.mkdir(exist_ok=True)

    # Process each file, reusing one engine (run_analysis resets all per-run
    # state, and constructing an engine re-scans plugin directories).
    success_count = 0
    fail_count = 0
    engine = TitanEngine(config)
    assurance_engine = None
    if config.get("enable_assurance", True):
        from .core.assurance import AssuranceEngine

        assurance_engine = AssuranceEngine(config._config)

    for i, file_path in enumerate(files, 1):
        if not getattr(args, "quiet", False):
            print(f"\n[{i}/{len(files)}] Analyzing {file_path.name}...")

        try:
            # Read file
            data = file_path.read_bytes()

            # Run analysis
            if getattr(args, "offline", False):
                with block_network():
                    report = engine.run_analysis(data)
                    report.setdefault("meta", {})
                    report["meta"]["network_blocked"] = is_network_blocked()
            else:
                report = engine.run_analysis(data)

            report.setdefault("meta", {})
            report["meta"]["offline"] = bool(getattr(args, "offline", False))
            report["meta"]["enrichment_requested"] = bool(
                getattr(args, "enable_enrichment", False)
            )
            report["meta"].setdefault(
                "network_blocked", bool(getattr(args, "offline", False))
            )
            if assurance_engine is not None:
                from .core.assurance_providers import AssuranceProviderRunner

                AssuranceProviderRunner(config._config).collect(
                    file_path,
                    report,
                    allow_external=not getattr(args, "offline", False),
                )
                assurance_engine.run_static_checks(report, engine.artifact_payloads())
                report["assurance"] = assurance_engine.evaluate(report)

            # Strict validation (contract enforcement)
            if bool(config.get("strict", False)):
                ok, errors = _validate_report_contract(report)
                if not ok:
                    raise ValueError(f"Strict validation failed: {errors}")

            report_json = json.dumps(report, indent=2)

            # Report size guard (optional)
            max_mb = config.get("max_report_size_mb")
            if max_mb is not None:
                max_bytes = int(float(max_mb) * 1024 * 1024)
                if len(report_json.encode("utf-8")) > max_bytes:
                    raise ValueError(f"Report exceeds max-report-size-mb ({max_mb} MB)")

            # Save report
            report_path = output_dir / f"{file_path.stem}_report.json"
            report_path.write_text(report_json, encoding="utf-8")

            # Optional vault storage
            if getattr(args, "vault_store", False):
                _vault_store(config, report)

            if not getattr(args, "quiet", False):
                print(
                    f"  ✓ Success: {report['node_count']} nodes, {sum(len(v) for v in report.get('iocs', {}).values())} IOCs"
                )
                print(f"  Report: {report_path}")
            success_count += 1

        except KeyboardInterrupt:
            print("\nBatch analysis interrupted by user")
            break
        except Exception as e:
            print(f"  ✗ Failed: {e}")
            fail_count += 1
            if args.verbose:
                import traceback

                traceback.print_exc()

    # Summary
    if not getattr(args, "quiet", False):
        print(f"\n{'=' * 80}")
        print("BATCH ANALYSIS COMPLETE")
        print(f"{'=' * 80}")
        print(f"Total files:   {len(files)}")
        print(f"Successful:    {success_count}")
        print(f"Failed:        {fail_count}")
        print(f"Reports saved: {output_dir}")
        print(f"{'=' * 80}")

    return 0 if fail_count == 0 else 1


if __name__ == "__main__":
    main()
