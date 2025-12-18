#!/usr/bin/env python3

import argparse
import json
import logging
import sys
from pathlib import Path

from .core.engine import TitanEngine
from .core.device_forensics import ForensicsEngine
from .config import Config


def main():
    parser = argparse.ArgumentParser(
        description="Titan Decoder Engine - Advanced payload analysis tool"
    )
    parser.add_argument(
        "--file", "-f",
        type=Path,
        help="Input file to analyze"
    )
    parser.add_argument(
        "--out", "-o",
        type=Path,
        help="Output JSON report file"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose logging"
    )
    parser.add_argument(
        "--max-depth",
        type=int,
        help="Maximum recursion depth (overrides config)"
    )
    parser.add_argument(
        "--config",
        type=Path,
        help="Configuration file path"
    )
    parser.add_argument(
        "--graph",
        type=Path,
        help="Export analysis graph to file"
    )
    parser.add_argument(
        "--graph-format",
        choices=["json", "dot", "mermaid"],
        default="json",
        help="Graph export format (default: json)"
    )
    parser.add_argument(
        "--profile",
        action="store_true",
        help="Enable performance profiling with cProfile"
    )
    parser.add_argument(
        "--profile-out",
        type=Path,
        help="Save performance profile output to file"
    )
    parser.add_argument(
        "--benchmark",
        action="store_true",
        help="Run comprehensive benchmark suite instead of normal analysis"
    )
    parser.add_argument(
        "--benchmark-out",
        type=Path,
        help="Save benchmark results to JSON file"
    )
    parser.add_argument(
        "--forensics-out",
        type=Path,
        help="Save forensic attribution summary to JSON file"
    )
    parser.add_argument(
        "--forensics-print",
        action="store_true",
        help="Print forensic attribution summary to stdout"
    )
    parser.add_argument(
        "--ioc-out",
        type=Path,
        help="Export IOCs to file (use with --ioc-format)"
    )
    parser.add_argument(
        "--ioc-format",
        choices=["json", "csv", "stix", "misp"],
        default="json",
        help="IOC export format (json, csv, stix, misp)"
    )
    parser.add_argument(
        "--report-out",
        type=Path,
        help="Save case report (markdown)"
    )
    parser.add_argument(
        "--timeline-out",
        type=Path,
        help="Export analysis timeline"
    )
    parser.add_argument(
        "--timeline-format",
        choices=["json", "csv"],
        default="json",
        help="Timeline export format (json, csv)"
    )
    parser.add_argument(
        "--profile",
        choices=["fast", "full"],
        help="Analysis profile: 'fast' for quick triage, 'full' for deep analysis"
    )
    parser.add_argument(
        "--max-artifacts",
        type=int,
        help="Maximum number of artifacts to extract (overrides config)"
    )
    parser.add_argument(
        "--progress",
        action="store_true",
        help="Show progress information during analysis"
    )
    parser.add_argument(
        "--enable-enrichment",
        action="store_true",
        help="Enable geo/WHOIS/YARA enrichment (requires config)"
    )
    parser.add_argument(
        "--enable-detections",
        action="store_true",
        help="Run detection rules and compute risk score"
    )
    parser.add_argument(
        "--enable-redaction",
        action="store_true",
        default=True,
        help="Enable PII redaction in logs (default: enabled)"
    )
    args = parser.parse_args()

    # Handle benchmark mode
    if args.benchmark:
        from .benchmarks import TitanBenchmarks
        benchmarks = TitanBenchmarks()
        benchmarks.run_all_benchmarks()
        
        if args.benchmark_out:
            benchmarks.suite.export_results_json(str(args.benchmark_out))
        return

    # Normal analysis mode
    if not args.file:
        print("Error: --file is required for normal analysis (or use --benchmark)")
        sys.exit(1)

    # Load configuration
    config = Config(args.config) if args.config else Config()

    # Apply profile presets
    if args.profile == "fast":
        config.set("max_recursion_depth", 3)
        config.set("max_node_count", 50)
        config.set("enable_parallel_extraction", False)
    elif args.profile == "full":
        config.set("max_recursion_depth", 8)
        config.set("max_node_count", 200)
        config.set("enable_parallel_extraction", True)

    # Override max depth if specified
    if args.max_depth:
        config.set("max_recursion_depth", args.max_depth)
    
    # Override max artifacts
    if args.max_artifacts:
        config.set("max_node_count", args.max_artifacts)
    
    # Setup secure logging with PII redaction
    if config.get("enable_logging", True):
        from .core.secure_logging import setup_secure_logging
        level = "DEBUG" if args.verbose else config.get("log_level", "INFO")
        secure_logger = setup_secure_logging(level, enable_redaction=args.enable_redaction)

    if not args.file.exists():
        print(f"Error: Input file {args.file} does not exist")
        sys.exit(1)

    # Read input data
    data = args.file.read_bytes()

    # Run analysis with optional profiling
    engine = TitanEngine(config)
    
    if args.profile:
        from .core.profiling import PerformanceProfiler
        profiler = PerformanceProfiler()
        
        with profiler.profile(enable_cprofile=True) as metrics:
            report = engine.run_analysis(data)
        
        # Print profiling results
        print("\n" + "="*80)
        print("PERFORMANCE PROFILE RESULTS")
        print("="*80)
        print(f"Execution Time:    {metrics.execution_time:.4f} seconds")
        print(f"Memory Peak:       {metrics.memory_peak:.2f} MB")
        print(f"Memory Average:    {metrics.memory_average:.2f} MB")
        print(f"CPU Usage:         {metrics.cpu_percent:.2f}%")
        print(f"Nodes Processed:   {metrics.operation_count}")
        print(f"Throughput:        {metrics.throughput:.2f} nodes/sec")
        print(f"Function Calls:    {metrics.function_calls}")
        
        if metrics.top_functions:
            print("\nTop 10 Slowest Functions:")
            for i, (func, time_taken) in enumerate(sorted(
                metrics.top_functions.items(), 
                key=lambda x: x[1], 
                reverse=True)[:10], 1):
                print(f"  {i:2d}. {func:<50} {time_taken:.4f}s")
        
        print("="*80 + "\n")
        
        if args.profile_out:
            # Save profile data
            profile_data = {
                'execution_time': metrics.execution_time,
                'memory_peak': metrics.memory_peak,
                'memory_average': metrics.memory_average,
                'cpu_percent': metrics.cpu_percent,
                'operation_count': metrics.operation_count,
                'throughput': metrics.throughput,
                'function_calls': metrics.function_calls,
                'top_functions': metrics.top_functions,
            }
            args.profile_out.write_text(json.dumps(profile_data, indent=2))
            print(f"Profile saved to {args.profile_out}")
    else:
        if args.progress:
            print("Starting analysis...")
        report = engine.run_analysis(data)
        if args.progress:
            print(f"Analysis complete: {report['node_count']} nodes generated")

    # Run detections and risk scoring if requested
    detections = []
    risk_assessment = None
    if args.enable_detections:
        if args.progress:
            print("Running detection rules...")
        from .core.detection_rules import CorrelationRulesEngine
        from .core.risk_scoring import RiskScoringEngine
        from .core.ioc_export import build_ioc_summary
        
        rules_engine = CorrelationRulesEngine()
        iocs = build_ioc_summary(report, None)
        detections = rules_engine.evaluate_all(report, iocs)
        
        risk_engine = RiskScoringEngine()
        risk_assessment = risk_engine.compute_risk_score(report, iocs, detections)
        
        if args.progress:
            print(f"Detections: {len(detections)} rules triggered")
            print(f"Risk Level: {risk_assessment['risk_level']} (Score: {risk_assessment['risk_score']}")

    # Optional enrichment
    enrichment_data = None
    if args.enable_enrichment:
        if args.progress:
            print("Enriching IOCs...")
        from .core.enrichment import EnrichmentEngine
        from .core.ioc_export import build_ioc_summary
        
        enrichment_engine = EnrichmentEngine(config._config)
        iocs = build_ioc_summary(report, None)
        enrichment_data = enrichment_engine.enrich_iocs(iocs)
        enrichment_engine.cleanup()
        
        if args.progress:
            print("Enrichment complete")

    # Optional forensic attribution summary
    forensics_summary = None
    if args.forensics_out or args.forensics_print:
        forensics = ForensicsEngine()
        forensics_summary = forensics.analyze(report)
    else:
        forensics_summary = None

    # Optional IOC export / case report / correlation
    if args.ioc_out or args.report_out:
        from .core.ioc_export import build_ioc_summary, export_iocs
        from .core.case_report import build_case_report, to_markdown
        iocs = build_ioc_summary(report, forensics_summary)

        # Correlation (optional, config-driven)
        if config.get("enable_correlation", False):
            from .core.correlation import CorrelationStore
            db_path = config.get("correlation_db_path") or (Path.home() / ".titan_decoder" / "correlation.db")
            db_path.parent.mkdir(parents=True, exist_ok=True)
            with CorrelationStore(db_path) as store:
                store.record_analysis(report.get("meta", {}).get("version", "analysis"), iocs)
                matches = store.correlate(iocs)
                if matches:
                    if not forensics_summary:
                        forensics_summary = {}
                    forensics_summary["correlation_matches"] = matches

        if args.ioc_out:
            export_iocs(iocs, args.ioc_out, args.ioc_format)
            print(f"IOCs exported to {args.ioc_out} ({args.ioc_format})")

        if args.report_out:
            case = build_case_report(report, forensics_summary, iocs)
            args.report_out.write_text(to_markdown(case))
            print(f"Case report saved to {args.report_out}")

    # Timeline export
    if args.timeline_out:
        from .core.timeline import build_timeline, export_timeline
        timeline = build_timeline(report)
        export_timeline(timeline, args.timeline_out, args.timeline_format)
        print(f"Timeline exported to {args.timeline_out} ({args.timeline_format})")

    # Export graph if requested
    if args.graph:
        try:
            engine.save_graph(args.graph, args.graph_format)
            print(f"Graph exported to {args.graph} (format: {args.graph_format})")
        except Exception as e:
            print(f"Error exporting graph: {e}")

    # Output results
    if args.out:
        args.out.write_text(json.dumps(report, indent=2))
        print(f"Report saved to {args.out}")
    else:
        print(json.dumps(report, indent=2))

    if forensics_summary:
        if args.forensics_out:
            args.forensics_out.write_text(json.dumps(forensics_summary, indent=2))
            print(f"Forensics summary saved to {args.forensics_out}")
        if args.forensics_print:
            print("\nFORENSICS SUMMARY:\n" + json.dumps(forensics_summary, indent=2))

    # Summary footer
    print("\n" + "="*80)
    print(f"TITAN ENGINE ANALYSIS COMPLETE — v{report['meta']['version']}")
    print("="*80)
    print(f"Nodes Generated:   {report['node_count']}")
    print(f"IOCs Found:        {sum(len(v) for v in report.get('iocs', {}).values())}")
    if detections:
        print(f"Detections:        {len(detections)} rules triggered")
    if risk_assessment:
        print(f"Risk Level:        {risk_assessment['risk_level']} (Score: {risk_assessment['risk_score']}/100)")
        if risk_assessment.get('top_reasons'):
            print(f"Top Risk Factors:  {', '.join(risk_assessment['top_reasons'][:3])}")
    print("="*80)

if __name__ == "__main__":
    main()