"""Performance profiling and benchmarking infrastructure for Titan Decoder.

This module provides tools for measuring performance, memory usage, and resource
consumption of the decoding engine and individual components.
"""

import time
import cProfile
import pstats
import io
import psutil
import os
from typing import Callable, Dict, List
from dataclasses import dataclass, field
from contextlib import contextmanager


@dataclass
class PerformanceMetrics:
    """Container for performance measurement results."""

    execution_time: float = 0.0  # Total execution time in seconds
    memory_peak: float = 0.0  # Peak memory usage in MB
    memory_average: float = 0.0  # Average memory usage in MB
    cpu_percent: float = 0.0  # CPU usage percentage
    function_calls: int = 0  # Total function calls during execution
    top_functions: Dict[str, float] = field(
        default_factory=dict
    )  # Top 10 slowest functions
    operation_count: int = 0  # Number of operations/nodes processed
    throughput: float = 0.0  # Operations per second


class PerformanceProfiler:
    """Profile performance of Titan Decoder operations."""

    def __init__(self):
        self.process = psutil.Process(os.getpid())
        self.start_time = None
        self.end_time = None
        self.start_memory = None
        self.end_memory = None
        self.memory_samples: List[float] = []
        self.profiler = None
        self.metrics = PerformanceMetrics()

    @contextmanager
    def profile(self, enable_cprofile: bool = False):
        """Context manager for profiling a code block.

        Args:
            enable_cprofile: If True, use cProfile for detailed function profiling

        Yields:
            PerformanceMetrics object to be populated
        """
        self._start_profiling(enable_cprofile)
        try:
            yield self.metrics
        finally:
            self._end_profiling()

    def _start_profiling(self, enable_cprofile: bool = False):
        """Start profiling session."""
        self.start_time = time.time()
        self.start_memory = self.process.memory_info().rss / 1024 / 1024  # MB
        self.memory_samples = [self.start_memory]

        if enable_cprofile:
            self.profiler = cProfile.Profile()
            self.profiler.enable()

    def _end_profiling(self):
        """End profiling session and collect metrics."""
        self.end_time = time.time()
        self.end_memory = self.process.memory_info().rss / 1024 / 1024  # MB

        # Calculate metrics
        self.metrics.execution_time = self.end_time - self.start_time
        self.metrics.memory_peak = max(self.memory_samples)
        self.metrics.memory_average = sum(self.memory_samples) / len(
            self.memory_samples
        )

        # CPU usage from process
        try:
            self.metrics.cpu_percent = self.process.cpu_percent(interval=0.1)
        except Exception:
            self.metrics.cpu_percent = 0.0

        # Get cProfile results if enabled
        if self.profiler:
            self.profiler.disable()
            self._extract_cprofile_data()

    def _extract_cprofile_data(self):
        """Extract data from cProfile profiler."""
        if not self.profiler:
            return

        s = io.StringIO()
        ps = pstats.Stats(self.profiler, stream=s).sort_stats("cumulative")
        ps.print_stats(10)  # Top 10 functions

        # Parse the output to extract function information
        stats_output = s.getvalue()
        self.metrics.top_functions = self._parse_pstats(stats_output)

        # Get total function calls from the stats
        try:
            self.metrics.function_calls = sum(1 for _ in self.profiler.getstats())
        except Exception:
            self.metrics.function_calls = 0

    def _parse_pstats(self, stats_output: str) -> Dict[str, float]:
        """Parse pstats output to extract function timing."""
        functions = {}
        lines = stats_output.split("\n")

        for line in lines:
            if "/" in line and "cumtime" not in line and "ncalls" not in line:
                parts = line.split()
                if len(parts) >= 5:
                    try:
                        func_name = parts[-1]
                        cumtime = float(parts[-4])
                        functions[func_name] = cumtime
                    except (ValueError, IndexError):
                        pass

        return functions

    def record_memory_sample(self):
        """Record current memory usage."""
        current_memory = self.process.memory_info().rss / 1024 / 1024
        self.memory_samples.append(current_memory)


class BenchmarkSuite:
    """Collection of benchmark tests for Titan Decoder."""

    def __init__(self):
        self.results: Dict[str, PerformanceMetrics] = {}

    def benchmark_decoding(
        self, engine, test_data: bytes, name: str, enable_cprofile: bool = False
    ) -> PerformanceMetrics:
        """Benchmark a single decoding operation.

        Args:
            engine: TitanEngine instance
            test_data: Data to decode
            name: Name of this benchmark
            enable_cprofile: Enable detailed cProfile profiling

        Returns:
            PerformanceMetrics with results
        """
        profiler = PerformanceProfiler()

        with profiler.profile(enable_cprofile=enable_cprofile) as metrics:
            report = engine.run_analysis(test_data)
            metrics.operation_count = report["node_count"]

            # Calculate throughput
            if metrics.execution_time > 0:
                metrics.throughput = metrics.operation_count / metrics.execution_time

        self.results[name] = profiler.metrics
        return profiler.metrics

    def benchmark_multiple_sizes(
        self, engine, base_data: bytes, sizes: List[int], name_prefix: str = "size_"
    ) -> Dict[int, PerformanceMetrics]:
        """Benchmark decoding with multiple data sizes.

        Args:
            engine: TitanEngine instance
            base_data: Base data to replicate
            sizes: List of sizes to test
            name_prefix: Prefix for benchmark names

        Returns:
            Dictionary mapping size to PerformanceMetrics
        """
        results = {}

        for size in sizes:
            # Adjust data to approximate target size
            multiplier = max(1, size // len(base_data))
            test_data = (base_data * multiplier)[:size]

            name = f"{name_prefix}{size}_bytes"
            metrics = self.benchmark_decoding(engine, test_data, name)
            results[size] = metrics

        return results

    def benchmark_recursion_depth(
        self, engine, create_nested_data: Callable, max_depth: int = 5
    ) -> Dict[int, PerformanceMetrics]:
        """Benchmark decoding with increasing recursion depth.

        Args:
            engine: TitanEngine instance
            create_nested_data: Callable that takes depth and returns encoded data
            max_depth: Maximum recursion depth to test

        Returns:
            Dictionary mapping depth to PerformanceMetrics
        """
        results = {}

        for depth in range(1, max_depth + 1):
            test_data = create_nested_data(depth)
            name = f"recursion_depth_{depth}"
            metrics = self.benchmark_decoding(engine, test_data, name)
            results[depth] = metrics

        return results

    def print_results(self, name: str = None):
        """Print benchmark results in a formatted table.

        Args:
            name: Optional specific benchmark to print. If None, print all.
        """
        if name:
            results = {name: self.results[name]} if name in self.results else {}
        else:
            results = self.results

        if not results:
            print("No results to display")
            return

        print("\n" + "=" * 100)
        print(
            f"{'Benchmark':<40} {'Time (s)':<12} {'Nodes':<10} {'Throughput':<15} {'Mem Peak':<12}"
        )
        print("-" * 100)

        for bench_name, metrics in results.items():
            print(
                f"{bench_name:<40} {metrics.execution_time:<12.4f} "
                f"{metrics.operation_count:<10} {metrics.throughput:<15.2f} "
                f"{metrics.memory_peak:<12.2f}"
            )

        print("=" * 100 + "\n")

    def export_results_json(self, filepath: str):
        """Export benchmark results to JSON file.

        Args:
            filepath: Path to save JSON results
        """
        import json

        export_data = {}
        for name, metrics in self.results.items():
            export_data[name] = {
                "execution_time": metrics.execution_time,
                "memory_peak": metrics.memory_peak,
                "memory_average": metrics.memory_average,
                "cpu_percent": metrics.cpu_percent,
                "operation_count": metrics.operation_count,
                "throughput": metrics.throughput,
                "top_functions": metrics.top_functions,
            }

        with open(filepath, "w") as f:
            json.dump(export_data, f, indent=2)

        print(f"Results exported to {filepath}")
