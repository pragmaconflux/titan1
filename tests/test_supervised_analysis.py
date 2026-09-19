"""Real spawned-worker checks; run on Windows as well as Linux."""

import json
import multiprocessing
import os
from pathlib import Path
import threading
import time
from contextlib import contextmanager

import pytest

from titan_decoder.config import Config
from titan_decoder.core import supervised_analysis
from titan_decoder.core.supervised_analysis import (
    AnalysisTerminated,
    _supervise,
    _write_result,
    analyze_supervised,
    main,
)


def _hang(marker):
    Path(marker).write_text(str(os.getpid()))
    while True:
        time.sleep(0.01)


def _large_report():
    return {"payload": "x" * 10000}


def _crash():
    os._exit(7)


def _exception():
    raise RuntimeError("private sample content")


def _allocate():
    # Above the test worker's OS allocation limit, not an RSS polling race.
    return {"size": len(bytearray(1024 * 1024 * 1024))}


def _run(operation, args=(), **overrides):
    options = dict(timeout=15, max_output_bytes=1024 * 1024, max_memory_mb=512)
    options.update(overrides)
    return _supervise(operation, args, **options)


def test_supervised_real_analysis_preserves_report():
    from titan_decoder.core.engine import TitanEngine

    report = analyze_supervised(b"hello ordinary world", timeout=20)
    assert report["node_count"] >= 1
    assert report["nodes"][0]["source_length"] == 20
    assert "analysis_outcome" in report
    assert "run_manifest" in report
    config = Config.__new__(Config)
    config._config = Config.DEFAULT_CONFIG.copy()
    expected = TitanEngine(config).run_analysis(b"hello ordinary world")
    for field in ("nodes", "iocs", "analysis_outcome"):
        assert report[field] == expected[field]


def test_memory_limit_setup_failure_prevents_operation(tmp_path, monkeypatch):
    @contextmanager
    def unavailable(_limit):
        raise OSError("cannot install OS limit")
        yield

    called = []
    monkeypatch.setattr(supervised_analysis, "memory_limit", unavailable)
    supervised_analysis._worker(
        lambda: called.append(True), (), str(tmp_path), 100, 100
    )
    assert not called
    assert (tmp_path / "error").read_text() == "worker_failed"
    assert not (tmp_path / "report.json").exists()


def test_hung_worker_is_killed_and_reaped(tmp_path):
    before = {child.pid for child in multiprocessing.active_children()}
    marker = tmp_path / "started"
    started = time.monotonic()
    with pytest.raises(AnalysisTerminated, match="timeout"):
        _run(_hang, (str(marker),), timeout=3)
    assert marker.exists(), "test must reach the hanging operation"
    assert time.monotonic() - started < 10
    assert {child.pid for child in multiprocessing.active_children()} == before


def test_running_worker_can_be_cancelled(tmp_path):
    marker = tmp_path / "started"
    cancel = threading.Event()

    def cancel_after_start():
        deadline = time.monotonic() + 10
        while not marker.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        cancel.set()

    thread = threading.Thread(target=cancel_after_start)
    thread.start()
    try:
        with pytest.raises(AnalysisTerminated, match="cancelled"):
            _run(_hang, (str(marker),), cancel_event=cancel)
    finally:
        cancel.set()
        thread.join()
    assert marker.exists()


def test_pre_cancelled_does_not_start_worker():
    cancel = threading.Event()
    cancel.set()
    with pytest.raises(AnalysisTerminated, match="cancelled"):
        _run(_large_report, cancel_event=cancel)


@pytest.mark.parametrize(
    "operation,reason",
    [
        (_large_report, "output_limit"),
        (_crash, "worker_failed"),
        (_exception, "worker_failed"),
        (_allocate, "memory_limit"),
    ],
)
def test_worker_failures_never_return_partial_reports(operation, reason):
    with pytest.raises(AnalysisTerminated, match=reason):
        _run(operation, max_output_bytes=128)


@pytest.mark.parametrize("timeout", [0, -1, float("nan"), float("inf")])
def test_invalid_deadline_rejected(timeout):
    with pytest.raises(ValueError):
        _run(_large_report, timeout=timeout)


@pytest.mark.parametrize("option", ["max_output_bytes", "max_memory_mb"])
def test_invalid_limits_rejected(option):
    with pytest.raises(ValueError):
        _run(_large_report, **{option: 0})


def test_input_limit_and_plugins_rejected():
    with pytest.raises(AnalysisTerminated, match="input_limit"):
        analyze_supervised(b"123", max_input_bytes=2)
    with pytest.raises(ValueError):
        analyze_supervised(b"123", max_input_bytes=0)
    config = Config()
    config.set("plugin_dirs", ["untrusted"])
    with pytest.raises(ValueError, match="external plugins"):
        analyze_supervised(b"123", config=config)


def test_exact_output_bound(tmp_path):
    path = tmp_path / "report.json"
    _write_result(path, {}, 2)
    assert path.read_bytes() == b"{}"
    with pytest.raises(AnalysisTerminated, match="output_limit"):
        _write_result(path, {}, 1)
    assert path.stat().st_size <= 1


def test_cli_failure_is_indeterminate(tmp_path, capsys):
    path = tmp_path / "sample"
    path.write_bytes(b"123")
    assert main(["--file", str(path), "--max-input-bytes", "2"]) == 2
    result = capsys.readouterr()
    assert result.out == ""
    assert json.loads(result.err) == {
        "status": "indeterminate",
        "reason": "input_limit",
    }


def test_cli_missing_file_is_not_clean(tmp_path, capsys):
    assert main(["--file", str(tmp_path / "missing")]) == 2
    assert json.loads(capsys.readouterr().err)["status"] == "indeterminate"


def test_cli_success(tmp_path, capsys):
    path = tmp_path / "sample"
    path.write_bytes(b"plain example")
    assert main(["--file", str(path)]) == 0
    assert json.loads(capsys.readouterr().out)["node_count"] >= 1
