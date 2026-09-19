"""A report must never claim a bound that nothing enforced.

Titan advertises a per-operation timeout and a memory ceiling, but both depend
on the host. SIGALRM is POSIX-and-main-thread-only, so the desktop UI's
analysis thread has no per-operation timeout on any platform, and
``check_memory_usage`` previously returned 0.0 when psutil was missing --
silently satisfying every ceiling while still appearing enforced. psutil is not
a base dependency, so that was the default headless install.

Degrading silently is the failure mode these tests exist to prevent: where a
bound cannot be enforced, the run records it as a limitation.
"""

import builtins
import threading

import pytest

from titan_decoder.config import Config
from titan_decoder.core.engine import TitanEngine
from titan_decoder.core.resource_manager import ResourceManager


@pytest.fixture
def no_memory_backend(monkeypatch):
    """Simulate a host with neither psutil nor the POSIX resource module."""
    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name in {"psutil", "resource"}:
            raise ImportError(name)
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)


def test_memory_usage_is_measurable_on_this_host():
    usage = ResourceManager({}).check_memory_usage()
    assert usage is not None and usage > 0


def test_stdlib_fallback_measures_memory_without_psutil(monkeypatch):
    # The common headless install has no psutil; resource.getrusage is stdlib
    # on POSIX, so the ceiling stays real rather than becoming a no-op.
    real_import = builtins.__import__

    def no_psutil(name, *args, **kwargs):
        if name == "psutil":
            raise ImportError(name)
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", no_psutil)
    usage = ResourceManager({}).check_memory_usage()
    assert usage is not None and usage > 0


def test_unmeasurable_memory_reports_none_not_zero(no_memory_backend):
    # 0.0 would silently satisfy every configured ceiling.
    manager = ResourceManager({})
    assert manager.check_memory_usage() is None
    assert manager.memory_enforcement_available() is False


def test_unmeasurable_memory_does_not_abort_analysis(no_memory_backend):
    # Failing closed here would abort every run on a host that simply cannot
    # measure itself; the limitation is reported instead.
    assert ResourceManager({}).should_abort_due_to_memory(1) is False


def test_unenforceable_memory_bound_is_reported(no_memory_backend):
    report = TitanEngine(Config()).run_analysis(b"calibration payload")
    assert "memory_bound_unenforced" in report["analysis_outcome"]["limitations"]


def test_timeout_enforcement_is_available_on_the_main_thread():
    assert ResourceManager({}).timeout_enforcement_available() is True


def test_worker_thread_reports_unenforceable_operation_timeout():
    # This is the desktop UI's path on every platform: analysis runs in a
    # QThread, where SIGALRM cannot be installed.
    captured = {}

    def run():
        report = TitanEngine(Config()).run_analysis(b"calibration payload")
        captured["limitations"] = report["analysis_outcome"]["limitations"]

    worker = threading.Thread(target=run)
    worker.start()
    worker.join()
    assert "operation_timeout_unenforced" in captured["limitations"]


def test_main_thread_run_does_not_claim_unenforced_timeout():
    report = TitanEngine(Config()).run_analysis(b"calibration payload")
    assert (
        "operation_timeout_unenforced" not in report["analysis_outcome"]["limitations"]
    )
