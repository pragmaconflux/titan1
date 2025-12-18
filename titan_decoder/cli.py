#!/usr/bin/env python3

import argparse
import json
import logging
import sys
from pathlib import Path

from .core.engine import TitanEngine
from .config import Config


def main():
    parser = argparse.ArgumentParser(
        description="Titan Decoder Engine - Advanced payload analysis tool"
    )
    parser.add_argument(
        "--file", "-f",
        type=Path,
        required=True,
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

    args = parser.parse_args()

    # Load configuration
    config = Config(args.config) if args.config else Config()

    # Override max depth if specified
    if args.max_depth:
        config.set("max_recursion_depth", args.max_depth)

    # Setup logging
    if config.get("enable_logging", True):
        level = getattr(logging, config.get("log_level", "INFO").upper())
        if args.verbose:
            level = logging.DEBUG
        logging.basicConfig(level=level, format='%(levelname)s: %(message)s')

    if not args.file.exists():
        print(f"Error: Input file {args.file} does not exist")
        sys.exit(1)

    # Read input data
    data = args.file.read_bytes()

    # Run analysis
    engine = TitanEngine(config)
    report = engine.run_analysis(data)

    # Output results
    if args.out:
        args.out.write_text(json.dumps(report, indent=2))
        print(f"Report saved to {args.out}")
    else:
        print(json.dumps(report, indent=2))

    print(f"\nTITAN ENGINE ANALYSIS COMPLETE — v{report['meta']['version']}")
    print(f"Nodes Generated: {report['node_count']}")


if __name__ == "__main__":
    main()