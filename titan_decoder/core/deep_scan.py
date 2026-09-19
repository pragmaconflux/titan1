"""Deterministic recursive static scanner with optional quarantine."""

from __future__ import annotations

from datetime import datetime, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import tempfile
import threading
from typing import Any, Callable, Mapping

from ..config import Config
from ..plugins import PluginContext
from .assurance import AssuranceEngine
from .assurance_providers import AssuranceProviderRunner
from .engine import TitanEngine
from .offline_guard import block_network
from .quarantine import QuarantineVault
from .supervised_analysis import AnalysisTerminated, analyze_supervised


class DeepScanner:
    """Scan a file tree without executing samples or following links by default."""

    def __init__(
        self,
        config: Config | None = None,
        *,
        progress_callback: Callable[[dict[str, Any]], None] | None = None,
        cancel_event: threading.Event | None = None,
        offline: bool = True,
        supervised: bool = False,
    ):
        self.config = config or Config()
        self.progress_callback = progress_callback
        self.cancel_event = cancel_event or threading.Event()
        self.offline = offline
        self.supervised = supervised

    def scan(
        self,
        target: Path,
        *,
        pattern: str = "*",
        reports_dir: Path | None = None,
        quarantine: QuarantineVault | None = None,
        quarantine_verdicts: set[str] | None = None,
        quarantine_move: bool = False,
        allow_external_providers: bool = False,
    ) -> dict[str, Any]:
        if self.supervised:
            if (
                not self.offline
                or allow_external_providers
                or self.config.get("enable_authenticode_provider", False)
            ):
                raise ValueError(
                    "supervised deep scan requires offline mode without external providers"
                )
            if self.config.get("plugin_dirs"):
                raise ValueError(
                    "supervised deep scan does not yet support external plugins"
                )
        configured_follow = bool(self.config.get("deep_scan_follow_symlinks", False))
        expanded_target = target.expanduser()
        if expanded_target.is_symlink() and not configured_follow:
            raise ValueError("deep scan refuses a symlink target by default")
        target = expanded_target.resolve()
        if not target.exists():
            raise FileNotFoundError(target)
        reports_dir = (
            reports_dir.expanduser().resolve()
            if reports_dir is not None
            else target.parent / f"{target.name}-titan-reports"
        )
        reports_dir.mkdir(parents=True, exist_ok=True)
        excluded_roots = {reports_dir}
        if quarantine is not None:
            excluded_roots.add(quarantine.root.expanduser().resolve())
        discovered = [
            path
            for path in self._candidates(target, pattern)
            if not any(path == root or root in path.parents for root in excluded_roots)
        ]
        max_files = max(1, int(self.config.get("deep_scan_max_files", 10000)))
        candidates = discovered[:max_files]
        engine = (
            None
            if self.supervised
            else TitanEngine(self.config, cancel_event=self.cancel_event)
        )
        assurance = AssuranceEngine(self.config._config)
        provider_runner = AssuranceProviderRunner(self.config._config)
        verdicts = {value.upper() for value in (quarantine_verdicts or set())}
        max_total = max(
            1,
            int(self.config.get("deep_scan_max_total_bytes", 10 * 1024 * 1024 * 1024)),
        )
        max_file = max(1, int(self.config.get("max_data_size", 50 * 1024 * 1024)))
        total_bytes = 0
        results: list[dict[str, Any]] = []
        errors: list[dict[str, str]] = []

        for index, path in enumerate(candidates, start=1):
            if self.cancel_event.is_set():
                break
            self._progress(index, len(candidates), path)
            try:
                size = path.stat().st_size
                if size > max_file:
                    raise ValueError(f"file exceeds the {max_file}-byte input limit")
                if total_bytes + size > max_total:
                    raise ValueError("deep-scan total byte limit reached")
                with path.open("rb") as handle:
                    data = handle.read(max_file + 1)
                if len(data) > max_file:
                    raise ValueError(f"file exceeds the {max_file}-byte input limit")
                if total_bytes + len(data) > max_total:
                    raise ValueError("deep-scan total byte limit reached")
                total_bytes += len(data)
                if self.supervised:
                    report = analyze_supervised(
                        data,
                        config=self.config,
                        timeout=float(self.config.get("analysis_timeout_seconds", 300)),
                        max_input_bytes=max_file,
                        max_output_bytes=int(
                            self.config.get(
                                "supervised_max_output_bytes", 16 * 1024 * 1024
                            )
                        ),
                        max_memory_mb=int(self.config.get("max_memory_mb", 1024)),
                        cancel_event=self.cancel_event,
                        static_checks=True,
                    )
                elif self.offline:
                    assert engine is not None
                    with block_network():
                        report = engine.run_analysis(data)
                else:
                    assert engine is not None
                    report = engine.run_analysis(data)
                if engine is not None:
                    self._run_detection_plugins(engine, report)
                if allow_external_providers or self.config.get(
                    "enable_authenticode_provider", False
                ):
                    provider_runner.collect(
                        path,
                        report,
                        allow_external=allow_external_providers and not self.offline,
                    )
                if engine is not None:
                    assurance.run_static_checks(report, engine.artifact_payloads())
                    report["assurance"] = assurance.evaluate(report)
                digest = sha256(data).hexdigest()
                report_path = reports_dir / self._report_name(path, target, digest)
                self._write_report(report_path, report)
                verdict = str(report["assurance"]["verdict"])
                quarantined = None
                if quarantine is not None and verdict in verdicts:
                    quarantined = quarantine.quarantine(
                        path,
                        verdict,
                        report_path=report_path,
                        move=quarantine_move,
                    ).to_dict()
                results.append(
                    {
                        "path": str(path),
                        "size": len(data),
                        "sha256": digest,
                        "verdict": verdict,
                        "risk_level": (report.get("risk_assessment") or {}).get(
                            "risk_level"
                        ),
                        "report_path": str(report_path),
                        "quarantine": quarantined,
                    }
                )
            except AnalysisTerminated as exc:
                errors.append(
                    {"path": str(path), "error": exc.reason, "status": "INDETERMINATE"}
                )
            except Exception as exc:
                errors.append({"path": str(path), "error": str(exc)[:1000]})

        return {
            "schema_version": "1.0",
            "started_target": str(target),
            "finished_at": datetime.now(timezone.utc).isoformat(),
            "offline": self.offline,
            "cancelled": self.cancel_event.is_set(),
            "discovered_count": len(discovered),
            "candidate_count": len(candidates),
            "candidate_limit_reached": len(discovered) > len(candidates),
            "analyzed_count": len(results),
            "error_count": len(errors),
            "total_bytes": total_bytes,
            "verdict_counts": {
                verdict: sum(item["verdict"] == verdict for item in results)
                for verdict in sorted({item["verdict"] for item in results})
            },
            "results": results,
            "errors": errors,
        }

    def _candidates(self, target: Path, pattern: str) -> list[Path]:
        follow = bool(self.config.get("deep_scan_follow_symlinks", False))
        if target.is_file():
            return [target]
        values = []
        for path in target.rglob(pattern):
            if not path.is_file():
                continue
            if not follow and (
                path.is_symlink()
                or any(
                    parent.is_symlink()
                    for parent in path.parents
                    if parent != target.parent
                )
            ):
                continue
            values.append(path)
        return sorted(values, key=lambda value: value.as_posix().casefold())

    @staticmethod
    def _report_name(path: Path, target: Path, digest: str) -> str:
        root = target if target.is_dir() else target.parent
        relative = path.relative_to(root).as_posix()
        label = re.sub(r"[^A-Za-z0-9._-]+", "_", relative).strip("._")
        identity = sha256(
            relative.encode("utf-8", errors="surrogateescape")
            + b"\0"
            + digest.encode("ascii")
        ).hexdigest()[:16]
        return f"{(label or 'sample')[:100]}.{identity}.json"

    @staticmethod
    def _write_report(path: Path, report: Mapping[str, Any]) -> None:
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            json.dump(dict(report), handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
            temporary = Path(handle.name)
        try:
            temporary.replace(path)
        finally:
            if temporary.exists():
                temporary.unlink()

    def _progress(self, current: int, total: int, path: Path) -> None:
        if self.progress_callback is None:
            return
        self.progress_callback(
            {
                "stage": "deep_scan",
                "percent": int(100 * (current - 1) / max(total, 1)),
                "message": f"Scanning {path.name}",
                "current": current,
                "total": total,
                "path": str(path),
            }
        )

    def _run_detection_plugins(
        self, engine: TitanEngine, report: dict[str, Any]
    ) -> None:
        context = PluginContext(config=self.config._config, offline=self.offline)
        existing = report.get("detections")
        detections = list(existing) if isinstance(existing, list) else []
        for plugin in engine.plugin_manager.get_detections():
            declared = {str(value) for value in plugin.rule_ids}
            try:
                findings = list(
                    plugin.detect(report, report.get("iocs") or {}, context)
                )
            except Exception:
                continue
            for finding in findings[:200]:
                value = finding.to_dict() if hasattr(finding, "to_dict") else None
                if isinstance(value, Mapping) and value.get("rule_id") in declared:
                    item = dict(value)
                    item["source"] = {"type": "plugin", "plugin": plugin.name}
                    detections.append(item)
        report["detections"] = detections
