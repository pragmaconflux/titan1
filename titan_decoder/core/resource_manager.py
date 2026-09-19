"""Resource management and timeout enforcement for safe analysis."""

from __future__ import annotations

import signal
import sys
import threading
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

    @contextmanager
    def timeout_context(self, seconds: int, operation_name: str = "operation"):
        """Context manager for enforcing timeouts on operations.

        SIGALRM-based timeouts only work on POSIX and only from the main
        thread. Elsewhere (Windows, worker threads) ``signal.signal`` raises,
        and since the engine swallows per-decoder exceptions that would
        silently disable every decoder/analyzer — so fall back to running the
        operation unguarded instead. The run-level wall-clock deadline and
        memory checks in the engine still bound the overall analysis.
        """
        sigalrm = getattr(signal, "SIGALRM", None)
        alarm = getattr(signal, "alarm", None)
        can_use_alarm = (
            sigalrm is not None
            and callable(alarm)
            and (threading.current_thread() is threading.main_thread())
        )
        if not can_use_alarm or seconds <= 0:
            if not can_use_alarm:
                logger.debug(
                    "SIGALRM unavailable (platform/thread); running %s without "
                    "a per-operation timeout",
                    operation_name,
                )
            yield
            return

        assert sigalrm is not None
        assert callable(alarm)

        def timeout_handler(signum, frame):
            raise TimeoutError(f"{operation_name} exceeded {seconds}s timeout")

        # Set up the timeout
        old_handler = signal.signal(sigalrm, timeout_handler)
        alarm(seconds)

        try:
            yield
        finally:
            # Restore original handler and cancel alarm
            alarm(0)
            signal.signal(sigalrm, old_handler)

    def memory_enforcement_available(self) -> bool:
        """Whether this process can actually measure its own memory use.

        ``max_memory_mb`` is advertised as a bound, so callers need to know
        when it cannot be enforced rather than discovering that a report
        claimed a limit nothing was checking.
        """
        return self.check_memory_usage() is not None

    def timeout_enforcement_available(self) -> bool:
        """Whether per-operation timeouts can actually interrupt an operation.

        SIGALRM is POSIX-only and main-thread-only, so this is False on
        Windows and in every worker thread -- including the desktop UI's
        analysis thread, which is the default entry point on all platforms.
        The run-level wall-clock deadline still applies between operations,
        but a parser that never returns cannot be interrupted.
        """
        sigalrm = getattr(signal, "SIGALRM", None)
        alarm = getattr(signal, "alarm", None)
        return (
            sigalrm is not None
            and callable(alarm)
            and threading.current_thread() is threading.main_thread()
        )

    def check_memory_usage(self) -> Optional[float]:
        """Return process memory use in MB, or None when it cannot be measured.

        Returning None rather than 0.0 matters: 0.0 silently satisfies every
        bound, so a missing psutil turned ``max_memory_mb`` into a no-op that
        still appeared enforced. ``resource.getrusage`` is in the standard
        library on POSIX and needs no dependency, so the common headless
        install keeps a real bound; it reports peak rather than current usage,
        which is the conservative direction for a limit.
        """
        try:
            import psutil

            process = psutil.Process()
            return float(process.memory_info().rss) / 1024 / 1024
        except ImportError:
            pass
        except Exception as e:
            logger.warning(f"Could not check memory usage: {e}")
            return None

        try:
            import resource
        except ImportError:
            return None  # Windows without psutil: no stdlib equivalent.
        try:
            usage = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        except (OSError, ValueError) as e:
            logger.warning(f"Could not check memory usage: {e}")
            return None
        # ru_maxrss is kilobytes on Linux and bytes on macOS.
        divisor = 1024.0 * 1024.0 if sys.platform == "darwin" else 1024.0
        return float(usage) / divisor

    def should_abort_due_to_memory(self, max_memory_mb: Optional[int] = None) -> bool:
        """Check if analysis should abort due to memory pressure."""
        if max_memory_mb is None:
            max_memory_mb = self.config.get("max_memory_mb", 1024)  # 1GB default

        current_mb = self.check_memory_usage()
        if current_mb is None:
            return False  # Unmeasurable; the caller records the limitation.
        if current_mb > max_memory_mb:
            logger.error(
                f"Memory limit exceeded: {current_mb:.1f}MB > {max_memory_mb}MB"
            )
            return True
        return False
