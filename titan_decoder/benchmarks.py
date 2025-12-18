"""Benchmark suite for comprehensive performance testing of Titan Decoder."""

import base64
import gzip
import zlib
from pathlib import Path
from titan_decoder.core.engine import TitanEngine
from titan_decoder.core.profiling import BenchmarkSuite, PerformanceProfiler
from titan_decoder.config import Config


class TitanBenchmarks:
    """Comprehensive benchmark suite for Titan Decoder."""
    
    def __init__(self):
        self.suite = BenchmarkSuite()
        self.engine = TitanEngine()
    
    def benchmark_simple_encodings(self):
        """Benchmark simple encoding types."""
        print("\n" + "="*100)
        print("BENCHMARK: Simple Encodings")
        print("="*100)
        
        # Base64
        data = b"Hello, World!" * 100
        self.suite.benchmark_decoding(self.engine, base64.b64encode(data), "base64_encoding")
        
        # Gzip
        self.suite.benchmark_decoding(self.engine, gzip.compress(data), "gzip_compression")
        
        # Zlib
        self.suite.benchmark_decoding(self.engine, zlib.compress(data), "zlib_compression")
        
        # Hex
        import binascii
        self.suite.benchmark_decoding(self.engine, binascii.hexlify(data), "hex_encoding")
        
        self.suite.print_results()
    
    def benchmark_nested_encodings(self):
        """Benchmark multiple layers of encoding."""
        print("\n" + "="*100)
        print("BENCHMARK: Nested Encodings")
        print("="*100)
        
        # Double base64
        data = b"Nested encoding test" * 50
        encoded1 = base64.b64encode(data)
        encoded2 = base64.b64encode(encoded1)
        self.suite.benchmark_decoding(self.engine, encoded2, "double_base64")
        
        # Base64 + Gzip
        data = b"Compression test" * 100
        gzipped = gzip.compress(data)
        b64_gzip = base64.b64encode(gzipped)
        self.suite.benchmark_decoding(self.engine, b64_gzip, "base64_gzip")
        
        # Triple nested
        data = b"Triple nested" * 40
        encoded = base64.b64encode(data)
        encoded = base64.b64encode(encoded)
        encoded = base64.b64encode(encoded)
        self.suite.benchmark_decoding(self.engine, encoded, "triple_base64")
        
        self.suite.print_results()
    
    def benchmark_data_sizes(self):
        """Benchmark with varying data sizes."""
        print("\n" + "="*100)
        print("BENCHMARK: Data Size Scaling")
        print("="*100)
        
        base_data = b"Test data for sizing benchmark. " * 10
        sizes = [1024, 10*1024, 100*1024, 1024*1024]  # 1KB, 10KB, 100KB, 1MB
        
        results = self.suite.benchmark_multiple_sizes(self.engine, base_data, sizes, "base64_")
        
        # Print with scaling analysis
        self.suite.print_results()
        
        # Calculate scaling factor
        size_list = sorted(results.keys())
        if len(size_list) >= 2:
            print("\nScaling Analysis:")
            for i in range(len(size_list) - 1):
                size1, size2 = size_list[i], size_list[i+1]
                time1 = results[size1].execution_time
                time2 = results[size2].execution_time
                size_ratio = size2 / size1
                time_ratio = time2 / time1 if time1 > 0 else 0
                print(f"  {size1} -> {size2} bytes: {size_ratio:.1f}x size, {time_ratio:.2f}x time")
    
    def benchmark_archive_extraction(self):
        """Benchmark ZIP and TAR archive extraction."""
        print("\n" + "="*100)
        print("BENCHMARK: Archive Extraction")
        print("="*100)
        
        import zipfile
        import tarfile
        import io
        
        # Create ZIP archive with multiple files
        zip_data = io.BytesIO()
        with zipfile.ZipFile(zip_data, 'w') as zf:
            for i in range(5):
                zf.writestr(f"file{i}.txt", b"Content of file " + str(i).encode() * 100)
        
        zip_content = zip_data.getvalue()
        encoded_zip = base64.b64encode(zip_content)
        self.suite.benchmark_decoding(self.engine, encoded_zip, "zip_extraction")
        
        # Create TAR archive
        tar_data = io.BytesIO()
        with tarfile.open(fileobj=tar_data, mode='w:gz') as tf:
            for i in range(5):
                import tarfile
                content = b"Content of tar file " + str(i).encode() * 100
                info = tarfile.TarInfo(name=f"file{i}.txt")
                info.size = len(content)
                tf.addfile(tarinfo=info, fileobj=io.BytesIO(content))
        
        tar_content = tar_data.getvalue()
        encoded_tar = base64.b64encode(tar_content)
        self.suite.benchmark_decoding(self.engine, encoded_tar, "tar_extraction")
        
        self.suite.print_results()
    
    def benchmark_with_profiling(self):
        """Run benchmark with detailed cProfile profiling."""
        print("\n" + "="*100)
        print("BENCHMARK: With cProfile Analysis")
        print("="*100)
        
        data = b"Profile test data" * 100
        encoded = base64.b64encode(data)
        
        # Run with profiling enabled
        profiler = PerformanceProfiler()
        with profiler.profile(enable_cprofile=True) as metrics:
            self.engine.run_analysis(encoded)
        
        print(f"\nExecution Time: {metrics.execution_time:.4f} seconds")
        print(f"Memory Peak: {metrics.memory_peak:.2f} MB")
        print(f"Function Calls: {metrics.function_calls}")
        print(f"CPU Usage: {metrics.cpu_percent:.2f}%")
        
        if metrics.top_functions:
            print("\nTop 10 Slowest Functions:")
            for i, (func, time_taken) in enumerate(sorted(metrics.top_functions.items(), 
                                                          key=lambda x: x[1], reverse=True)[:10], 1):
                print(f"  {i:2d}. {func:<50} {time_taken:.4f}s")
    
    def run_all_benchmarks(self):
        """Run all benchmark suites."""
        print("\n" + "#"*100)
        print("# TITAN DECODER - COMPREHENSIVE BENCHMARK SUITE")
        print("#"*100)
        
        self.benchmark_simple_encodings()
        self.benchmark_nested_encodings()
        self.benchmark_data_sizes()
        self.benchmark_archive_extraction()
        self.benchmark_with_profiling()
        
        # Export results
        self.suite.export_results_json("benchmark_results.json")
        
        print("\n" + "#"*100)
        print("# BENCHMARK SUITE COMPLETE")
        print("#"*100 + "\n")


def run_benchmarks():
    """Entry point for running benchmarks."""
    benchmarks = TitanBenchmarks()
    benchmarks.run_all_benchmarks()


if __name__ == "__main__":
    run_benchmarks()
