"""Opt-in supervised core analysis, independent of UI and in-process engine state.

Run ``python -m titan_decoder.core.supervised_analysis --help`` for the CLI.
This boundary limits one worker, not hostile plugins or their descendants.
"""

from __future__ import annotations

import argparse
import copy
import json
import math
import multiprocessing
from pathlib import Path
import sys
import tempfile
import time
from typing import Any, Callable

from .process_limits import memory_limit


class AnalysisTerminated(RuntimeError):
    """No complete report is available; never interpret this as a clean result."""

    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(reason)


def _write_result(path: Path, result: dict[str, Any], maximum: int) -> None:
    size = 0
    with path.open("wb") as stream:
        for chunk in json.JSONEncoder(ensure_ascii=True).iterencode(result):
            encoded = chunk.encode("ascii")
            size += len(encoded)
            if size > maximum:
                raise AnalysisTerminated("output_limit")
            stream.write(encoded)


def _worker(
    operation: Callable[..., dict[str, Any]],
    args: tuple,
    directory: str,
    maximum: int,
    memory_bytes: int,
) -> None:
    root = Path(directory)
    try:
        with memory_limit(memory_bytes):
            result = operation(*args)
            _write_result(root / "report.json", result, maximum)
    except AnalysisTerminated as exc:
        (root / "error").write_text(exc.reason, encoding="ascii")
    except MemoryError:
        (root / "error").write_text("memory_limit", encoding="ascii")
    except Exception:
        # Do not expose raw sample content or exception strings in diagnostics.
        (root / "error").write_text("worker_failed", encoding="ascii")


def _supervise(
    operation: Callable[..., dict[str, Any]],
    args: tuple,
    *,
    timeout: float,
    max_output_bytes: int,
    max_memory_mb: int,
    cancel_event: Any = None,
) -> dict[str, Any]:
    if not math.isfinite(timeout) or timeout <= 0:
        raise ValueError("timeout must be finite and positive")
    if max_output_bytes <= 0 or max_memory_mb <= 0:
        raise ValueError("output and memory limits must be positive")
    if cancel_event is not None and cancel_event.is_set():
        raise AnalysisTerminated("cancelled")
    context = multiprocessing.get_context("spawn")
    with tempfile.TemporaryDirectory(prefix="titan-analysis-") as directory:
        root = Path(directory)
        process = context.Process(
            target=_worker,
            args=(
                operation,
                args,
                directory,
                max_output_bytes,
                max_memory_mb * 1024 * 1024,
            ),
        )
        deadline = time.monotonic() + timeout
        try:
            process.start()
            while True:
                if cancel_event is not None and cancel_event.is_set():
                    raise AnalysisTerminated("cancelled")
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise AnalysisTerminated("timeout")
                process.join(min(0.02, remaining))
                if not process.is_alive():
                    break
            if process.exitcode != 0:
                raise AnalysisTerminated("worker_failed")
            if (root / "error").exists():
                reason = (
                    (root / "error").read_bytes()[:64].decode("ascii", errors="replace")
                )
                raise AnalysisTerminated(reason)
            report_path = root / "report.json"
            if not report_path.exists():
                raise AnalysisTerminated("worker_failed")
            with report_path.open("rb") as stream:
                encoded = stream.read(max_output_bytes + 1)
            if len(encoded) > max_output_bytes:
                raise AnalysisTerminated("output_limit")
            report = json.loads(encoded)
            if not isinstance(report, dict):
                raise AnalysisTerminated("invalid_report")
            return report
        finally:
            if process.pid is not None:
                if process.is_alive():
                    process.kill()
                process.join()
            process.close()


def _analyze(data: bytes, settings: dict[str, Any]) -> dict[str, Any]:
    from ..config import Config
    from .engine import TitanEngine
    from .offline_guard import block_network

    # Snapshot configuration without reading a second user config in the worker.
    config = Config.__new__(Config)
    config._config = settings
    config.config_file = Path.home() / ".titan_decoder" / "config.json"
    with block_network("supervised offline analysis"):
        return TitanEngine(config).run_analysis(data)


def analyze_supervised(
    data: bytes,
    *,
    config: Any = None,
    timeout: float = 300,
    max_input_bytes: int = 50 * 1024 * 1024,
    max_output_bytes: int = 16 * 1024 * 1024,
    max_memory_mb: int = 1024,
    cancel_event: Any = None,
) -> dict[str, Any]:
    """Return a core report or raise AnalysisTerminated; never return partial JSON.

    Uses OS allocation limits, not RSS sampling. Configured external plugins are
    rejected until descendant lifecycle containment is implemented. Call from
    an importable module with the usual ``if __name__ == '__main__'`` guard.
    """
    from ..config import Config

    if max_input_bytes <= 0:
        raise ValueError("input limit must be positive")
    if len(data) > max_input_bytes:
        raise AnalysisTerminated("input_limit")
    settings = copy.deepcopy(
        config._config if config is not None else Config.DEFAULT_CONFIG
    )
    if settings.get("plugin_dirs"):
        raise ValueError("supervised analysis does not yet support external plugins")
    return _supervise(
        _analyze,
        (data, settings),
        timeout=timeout,
        max_output_bytes=max_output_bytes,
        max_memory_mb=max_memory_mb,
        cancel_event=cancel_event,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Supervised offline Titan core analysis (not a sandbox)"
    )
    parser.add_argument("--file", required=True, type=Path)
    parser.add_argument("--timeout", type=float, default=300)
    parser.add_argument("--max-memory-mb", type=int, default=1024)
    parser.add_argument("--max-input-bytes", type=int, default=50 * 1024 * 1024)
    parser.add_argument("--max-output-bytes", type=int, default=16 * 1024 * 1024)
    options = parser.parse_args(argv)
    try:
        if options.max_input_bytes <= 0:
            raise ValueError("input limit must be positive")
        with options.file.open("rb") as stream:
            data = stream.read(options.max_input_bytes + 1)
        report = analyze_supervised(
            data,
            timeout=options.timeout,
            max_memory_mb=options.max_memory_mb,
            max_input_bytes=options.max_input_bytes,
            max_output_bytes=options.max_output_bytes,
        )
    except (AnalysisTerminated, ValueError, OSError) as exc:
        reason = (
            exc.reason if isinstance(exc, AnalysisTerminated) else "invalid_request"
        )
        print(
            json.dumps({"status": "indeterminate", "reason": reason}), file=sys.stderr
        )
        return 2
    print(json.dumps(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
