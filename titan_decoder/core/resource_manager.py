"""Resource management and timeout enforcement for safe analysis."""

from __future__ import annotations

import signal
import time
from contextlib import contextmanager
from typing import Optional
import logging

logger = logging.getLogger(__name__)


class TimeoutError(Exception):
    """Raised when an operation exceeds its timeout."""
    pass


class ResourceManager:
    """Manages resource limits and timeouts for analysis operations."""
    
    def __init__(self, config: dict):
        self.config = config
        self.analysis_timeout = config.get("analysis_timeout_seconds", 300)  # 5 minutes default
        self.decode_timeout = config.get("decode_timeout_seconds", 10)  # 10 seconds per decode
        
    @contextmanager
    def timeout_context(self, seconds: int, operation_name: str = "operation"):
        """Context manager for enforcing timeouts on operations."""
        def timeout_handler(signum, frame):
            raise TimeoutError(f"{operation_name} exceeded {seconds}s timeout")
        
        # Set up the timeout
        old_handler = signal.signal(signal.SIGALRM, timeout_handler)
        signal.alarm(seconds)
        
        try:
            yield
        finally:
            # Restore original handler and cancel alarm
            signal.alarm(0)
            signal.signal(signal.SIGALRM, old_handler)
    
    def check_memory_usage(self) -> float:
        """Check current memory usage in MB."""
        try:
            import psutil
            process = psutil.Process()
            return process.memory_info().rss / 1024 / 1024  # Convert to MB
        except ImportError:
            # psutil not available, can't check memory
            return 0.0
        except Exception as e:
            logger.warning(f"Could not check memory usage: {e}")
            return 0.0
    
    def should_abort_due_to_memory(self, max_memory_mb: Optional[int] = None) -> bool:
        """Check if analysis should abort due to memory pressure."""
        if max_memory_mb is None:
            max_memory_mb = self.config.get("max_memory_mb", 1024)  # 1GB default
        
        current_mb = self.check_memory_usage()
        if current_mb > max_memory_mb:
            logger.error(f"Memory limit exceeded: {current_mb:.1f}MB > {max_memory_mb}MB")
            return True
        return False
