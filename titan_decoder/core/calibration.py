"""Labeled decoder/analyzer calibration and quality metrics."""

from __future__ import annotations

import base64
from contextlib import contextmanager
from hashlib import sha256
import importlib.util
import json
from pathlib import Path
from typing import Any, Iterator, Mapping, Sequence

from ..config import Config
from .engine import TitanEngine


_CASE_CLASSES = frozenset(
    {
        "clean_negative",
        "malformed",
        "nested_chain",
        "positive",
        "size_bound",
        "truncated",
    }
)
_COMPONENT_KINDS = frozenset({"analyzer", "decoder"})

# Attributes through which a component declares how much output it will
# produce. Exposing one is what makes a component "amplifying", and therefore
# what makes a size_bound case meaningful for it. Decoders and analyzers name
# the same idea differently, so the lookup is per kind.
_OUTPUT_CAP_ATTRIBUTES_BY_KIND = {
    "decoder": ("max_output_size", "max_output"),
    "analyzer": ("max_total", "max_total_size"),
}
# Retained for callers that only care about decoders.
_OUTPUT_CAP_ATTRIBUTES = _OUTPUT_CAP_ATTRIBUTES_BY_KIND["decoder"]


def output_cap_attribute(kind: str, component: Any) -> str | None:
    """Return the attribute a component declares its output ceiling through."""
    for attribute in _OUTPUT_CAP_ATTRIBUTES_BY_KIND.get(kind, ()):
        if hasattr(component, attribute):
            return attribute
    return None


def _ratio(numerator: int, denominator: int) -> float:
    return round(numerator / denominator, 6) if denominator else 0.0


def _metrics(counts: Mapping[str, int]) -> dict[str, Any]:
    tp = int(counts.get("true_positive", 0))
    tn = int(counts.get("true_negative", 0))
    fp = int(counts.get("false_positive", 0))
    fn = int(counts.get("false_negative", 0))
    precision = _ratio(tp, tp + fp)
    recall = _ratio(tp, tp + fn)
    return {
        **dict(counts),
        "precision": precision,
        "recall": recall,
        "f1": _ratio(2 * tp, 2 * tp + fp + fn),
        "specificity": _ratio(tn, tn + fp),
        "accuracy": _ratio(tp + tn, tp + tn + fp + fn),
    }


def _empty_counts() -> dict[str, int]:
    return {
        "true_positive": 0,
        "true_negative": 0,
        "false_positive": 0,
        "false_negative": 0,
    }


def _outcome(expected: bool, predicted: bool) -> str:
    if expected and predicted:
        return "true_positive"
    if expected:
        return "false_negative"
    if predicted:
        return "false_positive"
    return "true_negative"


def _missing_modules(names: Sequence[object]) -> list[str]:
    missing: set[str] = set()
    for raw_name in names:
        name = str(raw_name)
        if not name:
            continue
        try:
            available = importlib.util.find_spec(name) is not None
        except (ImportError, ModuleNotFoundError, ValueError):
            available = False
        if not available:
            missing.add(name)
    return sorted(missing)


class CalibrationRunner:
    """Evaluate labeled cases against specific registered components."""

    def __init__(self, config: Config | None = None):
        self.config = config or Config()

    def run(self, corpus_path: Path) -> dict[str, Any]:
        corpus_path = corpus_path.expanduser().resolve()
        value = json.loads(corpus_path.read_text(encoding="utf-8"))
        if not isinstance(value, dict) or value.get("schema_version") != "1.0":
            raise ValueError("calibration corpus must use schema_version 1.0")
        cases = value.get("cases")
        if not isinstance(cases, list):
            raise ValueError("calibration corpus cases must be a list")
        case_definitions = {
            str(case.get("id")): case
            for case in cases
            if isinstance(case, dict) and case.get("id")
        }
        engine = TitanEngine(self.config)
        components: dict[str, dict[str, Any]] = {
            "decoder": {str(item.name): item for item in engine.decoders},
            "analyzer": {str(item.name): item for item in engine.analyzers},
        }
        builtin_components = self._builtin_components(engine)
        registry_keys = sorted(
            f"{kind}:{name}"
            for kind, items in builtin_components.items()
            for name in items
        )
        require_registry_parity_value = value.get("require_registry_parity", False)
        if not isinstance(require_registry_parity_value, bool):
            raise ValueError("require_registry_parity must be boolean")
        require_registry_parity = require_registry_parity_value
        required_case_classes = self._required_case_classes(value)
        if "exempt_components" in value:
            raise ValueError(
                "exempt_components is not supported; every live built-in must be "
                "covered by the calibration corpus"
            )
        details: list[dict[str, Any]] = []
        counts: dict[str, dict[str, int]] = {}
        recognition_counts: dict[str, dict[str, int]] = {}
        coverage: dict[str, dict[str, int]] = {}
        case_class_counts: dict[str, dict[str, int]] = {}
        skipped: list[dict[str, str]] = []
        dependency_skips: list[dict[str, Any]] = []
        label_failures: list[str] = []
        seen_case_ids: set[str] = set()
        for raw_case in cases:
            if not isinstance(raw_case, dict):
                label_failures.append("calibration case must be an object")
                continue
            case_id = str(raw_case.get("id") or f"case-{len(details) + 1}")
            if case_id in seen_case_ids:
                label_failures.append(f"{case_id}: duplicate case id")
            seen_case_ids.add(case_id)
            kind = str(raw_case.get("kind") or "")
            component_name = str(raw_case.get("component") or "")
            component = components.get(kind, {}).get(component_name)
            if component is None:
                skipped.append(
                    {
                        "id": case_id,
                        "reason": f"{kind} component is unavailable: {component_name}",
                    }
                )
                label_failures.append(
                    f"{case_id}: unknown or unavailable component "
                    f"{kind}:{component_name}"
                )
                continue
            key = f"{kind}:{component_name}"
            expected_match_value = raw_case.get("expected_match")
            expected_match = (
                expected_match_value if isinstance(expected_match_value, bool) else None
            )
            expected_recognition_value = raw_case.get(
                "expected_recognition", expected_match
            )
            if not isinstance(expected_recognition_value, bool):
                label_failures.append(
                    f"{case_id}: expected_recognition or expected_match must be boolean"
                )
                continue
            expected_recognition = expected_recognition_value
            if "expected_match" in raw_case and expected_match is None:
                label_failures.append(f"{case_id}: expected_match must be boolean")
                continue
            if expected_match is True and not expected_recognition:
                label_failures.append(
                    f"{case_id}: extraction cannot be positive when recognition is negative"
                )
                continue
            case_class_value = raw_case.get("case_class")
            if case_class_value is None:
                case_class = "positive" if expected_recognition else "clean_negative"
            elif (
                not isinstance(case_class_value, str)
                or case_class_value not in _CASE_CLASSES
            ):
                label_failures.append(
                    f"{case_id}: case_class must be one of "
                    f"{', '.join(sorted(_CASE_CLASSES))}"
                )
                continue
            else:
                case_class = case_class_value
            if case_class == "positive" and not expected_recognition:
                label_failures.append(
                    f"{case_id}: positive case_class requires positive recognition"
                )
                continue
            if case_class == "clean_negative" and expected_recognition:
                label_failures.append(
                    f"{case_id}: clean_negative case_class requires negative recognition"
                )
                continue
            required_modules = raw_case.get("required_modules") or []
            if not isinstance(required_modules, list) or not all(
                isinstance(name, str) and name for name in required_modules
            ):
                label_failures.append(
                    f"{case_id}: required_modules must be a list of module names"
                )
                continue
            unavailable_modules = _missing_modules(required_modules)
            try:
                data = self._case_data(
                    raw_case,
                    corpus_path.parent,
                    case_definitions=case_definitions,
                )
                with self._component_overrides(component, raw_case):
                    predicted_recognition, predicted_match, observation = (
                        self._evaluate(
                            kind,
                            component,
                            data,
                            raw_case,
                            evaluate_match=not unavailable_modules,
                        )
                    )
            except Exception as exc:
                predicted_recognition = False
                predicted_match = False if expected_match is not None else None
                error = f"{type(exc).__name__}: {exc}"
                observation = {"error": error}
                label_failures.append(f"{case_id}: evaluation error: {error}")
            evaluation_succeeded = "error" not in observation
            recognition_outcome = _outcome(expected_recognition, predicted_recognition)
            recognition_counts.setdefault(key, _empty_counts())[
                recognition_outcome
            ] += 1
            component_coverage = coverage.setdefault(
                key,
                {
                    "recognition_positive_cases": 0,
                    "recognition_negative_cases": 0,
                    "extraction_positive_cases": 0,
                    "extraction_negative_cases": 0,
                },
            )
            component_coverage[
                "recognition_positive_cases"
                if expected_recognition
                else "recognition_negative_cases"
            ] += 1
            if evaluation_succeeded:
                component_case_classes = case_class_counts.setdefault(key, {})
                component_case_classes[case_class] = (
                    component_case_classes.get(case_class, 0) + 1
                )
            match_outcome: str | None = None
            if expected_match is not None:
                component_coverage[
                    "extraction_positive_cases"
                    if expected_match
                    else "extraction_negative_cases"
                ] += 1
                if unavailable_modules:
                    dependency_skips.append(
                        {
                            "id": case_id,
                            "component": key,
                            "missing_modules": unavailable_modules,
                        }
                    )
                    predicted_match = None
                else:
                    match_outcome = _outcome(expected_match, bool(predicted_match))
                    counts.setdefault(key, _empty_counts())[match_outcome] += 1
            details.append(
                {
                    "id": case_id,
                    "kind": kind,
                    "component": component_name,
                    "case_class": case_class,
                    "expected_recognition": expected_recognition,
                    "predicted_recognition": predicted_recognition,
                    "recognition_outcome": recognition_outcome,
                    "expected_match": expected_match,
                    "predicted_match": predicted_match,
                    "outcome": match_outcome,
                    "missing_modules": unavailable_modules,
                    **observation,
                }
            )

        by_component = {key: _metrics(item) for key, item in sorted(counts.items())}
        recognition_by_component = {
            key: _metrics(item) for key, item in sorted(recognition_counts.items())
        }
        aggregate_counts = {
            label: sum(item[label] for item in counts.values())
            for label in (
                "true_positive",
                "true_negative",
                "false_positive",
                "false_negative",
            )
        }
        aggregate = _metrics(aggregate_counts)
        recognition_aggregate_counts = {
            label: sum(item[label] for item in recognition_counts.values())
            for label in (
                "true_positive",
                "true_negative",
                "false_positive",
                "false_negative",
            )
        }
        recognition_aggregate = _metrics(recognition_aggregate_counts)
        dependency_limited_components = {
            str(item["component"]) for item in dependency_skips
        }
        min_precision = float(self.config.get("calibration_min_precision", 0.90))
        min_recall = float(self.config.get("calibration_min_recall", 0.90))
        failures: list[Any] = [*label_failures]
        failures.extend(
            {
                "component": key,
                "phase": "extraction",
                "precision": item["precision"],
                "recall": item["recall"],
            }
            for key, item in by_component.items()
            if key not in dependency_limited_components
            and (item["precision"] < min_precision or item["recall"] < min_recall)
        )
        failures.extend(
            {
                "component": key,
                "phase": "recognition",
                "precision": item["precision"],
                "recall": item["recall"],
            }
            for key, item in recognition_by_component.items()
            if item["precision"] < min_precision or item["recall"] < min_recall
        )
        missing_positive: list[str] = []
        missing_negative: list[str] = []
        if require_registry_parity:
            for key in registry_keys:
                item = coverage.get(key, {})
                if int(item.get("recognition_positive_cases", 0)) < 1:
                    missing_positive.append(key)
                if int(item.get("recognition_negative_cases", 0)) < 1:
                    missing_negative.append(key)
            failures.extend(
                f"{key}: no positive recognition case" for key in missing_positive
            )
            failures.extend(
                f"{key}: no negative recognition case" for key in missing_negative
            )
        covered_registry = sorted(
            key
            for key in registry_keys
            if int(coverage.get(key, {}).get("recognition_positive_cases", 0)) >= 1
            and int(coverage.get(key, {}).get("recognition_negative_cases", 0)) >= 1
        )
        required_case_class_components = sorted(
            f"{kind}:{name}"
            for kind in required_case_classes
            for name in builtin_components[kind]
        )
        missing_case_classes: list[dict[str, str]] = []
        covered_case_class_components: list[str] = []
        for key in required_case_class_components:
            kind, _separator, _name = key.partition(":")
            missing_for_component = [
                case_class
                for case_class in required_case_classes[kind]
                if case_class_counts.get(key, {}).get(case_class, 0) < 1
            ]
            missing_case_classes.extend(
                {"component": key, "case_class": case_class}
                for case_class in missing_for_component
            )
            if not missing_for_component:
                covered_case_class_components.append(key)
        failures.extend(
            f"{item['component']}: no {item['case_class']} case"
            for item in missing_case_classes
        )
        # A size bound is only meaningful where a component can amplify. ROT13
        # and Base64 cannot produce more output than their input warrants, so
        # requiring the class of every component would demand fixtures that
        # measure nothing -- the same category error that keeps nested_chain
        # permanently zero. Derive the requirement from the live registry
        # instead: a component that exposes an output cap must prove it holds.
        size_bound_kinds = self._size_bound_kinds(value)
        amplifying_components = sorted(
            f"{kind}:{name}"
            for kind in size_bound_kinds
            for name, item in builtin_components[kind].items()
            if output_cap_attribute(kind, item) is not None
        )
        missing_size_bound = [
            key
            for key in amplifying_components
            if case_class_counts.get(key, {}).get("size_bound", 0) < 1
        ]
        failures.extend(
            f"{key}: exposes an output cap but has no size_bound case"
            for key in missing_size_bound
        )
        # Enforce the bound itself, not just the presence of a case. A case
        # that does not assert extraction -- because an optional module may be
        # absent -- still has to stay inside the cap it declares.
        failures.extend(
            f"{detail['id']}: emitted more than its declared output bound"
            for detail in details
            if detail.get("case_class") == "size_bound"
            and detail.get("output_within_bound") is False
        )
        return {
            "schema_version": "1.0",
            "corpus": str(corpus_path),
            "corpus_name": str(value.get("name") or corpus_path.stem),
            "case_count": len(details),
            "skipped_count": len(skipped),
            "aggregate": aggregate,
            "components": by_component,
            "recognition_aggregate": recognition_aggregate,
            "recognition_components": recognition_by_component,
            "registry_coverage": {
                "required": require_registry_parity,
                "live_builtin_components": registry_keys,
                "live_builtin_count": len(registry_keys),
                "covered_components": covered_registry,
                "covered_count": len(covered_registry),
                "missing_positive": missing_positive,
                "missing_negative": missing_negative,
                "per_component": {
                    key: coverage.get(
                        key,
                        {
                            "recognition_positive_cases": 0,
                            "recognition_negative_cases": 0,
                            "extraction_positive_cases": 0,
                            "extraction_negative_cases": 0,
                        },
                    )
                    for key in registry_keys
                },
            },
            "case_class_coverage": {
                "required_by_kind": required_case_classes,
                "required_components": required_case_class_components,
                "required_component_count": len(required_case_class_components),
                "covered_components": covered_case_class_components,
                "covered_count": len(covered_case_class_components),
                "missing": missing_case_classes,
                "per_component": {
                    key: {
                        case_class: case_class_counts.get(key, {}).get(case_class, 0)
                        for case_class in sorted(_CASE_CLASSES)
                    }
                    for key in registry_keys
                },
            },
            "quality_gate": {
                "passed": not failures and bool(details),
                "minimum_precision": min_precision,
                "minimum_recall": min_recall,
                "failures": failures,
            },
            "cases": details,
            "skipped": skipped,
            "dependency_skips": dependency_skips,
        }

    @staticmethod
    def _size_bound_kinds(value: Mapping[str, Any]) -> list[str]:
        """Component kinds whose amplifying members must prove their cap.

        Declared by the corpus rather than hardcoded so the requirement can be
        extended to analyzers once their oversized-input cases exist, without
        a code change.
        """
        raw = value.get("size_bound_required_kinds", [])
        if not isinstance(raw, list) or not all(isinstance(k, str) for k in raw):
            raise ValueError("size_bound_required_kinds must be a list of strings")
        unknown = sorted(set(raw) - _COMPONENT_KINDS)
        if unknown:
            raise ValueError(
                "size_bound_required_kinds must name decoder or analyzer: "
                + ", ".join(unknown)
            )
        return sorted(set(raw))

    @staticmethod
    def _required_case_classes(value: Mapping[str, Any]) -> dict[str, list[str]]:
        raw_requirements = value.get("required_case_classes", {})
        if not isinstance(raw_requirements, dict):
            raise ValueError("required_case_classes must be an object")
        requirements: dict[str, list[str]] = {}
        for kind, raw_classes in raw_requirements.items():
            if not isinstance(kind, str) or kind not in _COMPONENT_KINDS:
                raise ValueError(
                    "required_case_classes keys must be decoder or analyzer"
                )
            if not isinstance(raw_classes, list) or not all(
                isinstance(case_class, str) and case_class in _CASE_CLASSES
                for case_class in raw_classes
            ):
                raise ValueError(
                    f"required_case_classes.{kind} must be a list containing only "
                    f"{', '.join(sorted(_CASE_CLASSES))}"
                )
            if len(raw_classes) != len(set(raw_classes)):
                raise ValueError(
                    f"required_case_classes.{kind} must not contain duplicates"
                )
            requirements[kind] = sorted(raw_classes)
        return dict(sorted(requirements.items()))

    @staticmethod
    def _builtin_components(engine: TitanEngine) -> dict[str, dict[str, Any]]:
        """Return live built-ins without making user plugins corpus obligations."""

        plugin_decoders = {id(item) for item in engine.plugin_manager.get_decoders()}
        plugin_analyzers = {id(item) for item in engine.plugin_manager.get_analyzers()}
        return {
            "decoder": {
                str(item.name): item
                for item in engine.decoders
                if id(item) not in plugin_decoders
            },
            "analyzer": {
                str(item.name): item
                for item in engine.analyzers
                if id(item) not in plugin_analyzers
            },
        }

    @staticmethod
    def _case_data(
        value: Mapping[str, Any],
        root: Path,
        *,
        case_definitions: Mapping[str, Mapping[str, Any]] | None = None,
        resolving: frozenset[str] = frozenset(),
    ) -> bytes:
        representations = [
            key
            for key in (
                "data_text",
                "data_base64",
                "data_base64_parts",
                "data_hex",
                "fixture",
            )
            if key in value
        ]
        derive_from = value.get("derive_from")
        if derive_from is not None:
            if representations:
                raise ValueError(
                    "derived case cannot also declare a data representation"
                )
            source_id = str(derive_from)
            if not source_id or case_definitions is None:
                raise ValueError("derived case must reference a corpus case id")
            if source_id in resolving:
                raise ValueError("derived case references contain a cycle")
            source = case_definitions.get(source_id)
            if source is None:
                raise ValueError(f"derived case references unknown case: {source_id}")
            data = CalibrationRunner._case_data(
                source,
                root,
                case_definitions=case_definitions,
                resolving=resolving | {source_id},
            )
            mutation = value.get("mutation")
            if mutation is None:
                # Reuse another case's bytes unchanged. A size-bound case asks
                # a different question of the same fixture -- does the
                # component stay inside its cap -- so duplicating the payload
                # would only risk the two copies drifting apart.
                return data
            if mutation == "flip-middle-byte":
                if not data:
                    raise ValueError("cannot mutate an empty source case")
                index = len(data) // 2
                return data[:index] + bytes([data[index] ^ 0xFF]) + data[index + 1 :]
            if mutation == "truncate-half":
                if len(data) < 2:
                    raise ValueError(
                        "cannot truncate a source case shorter than 2 bytes"
                    )
                return data[: max(1, len(data) // 2)]
            raise ValueError(
                "derived case mutation must be flip-middle-byte or truncate-half"
            )
        if len(representations) != 1:
            raise ValueError(
                "case must declare exactly one data representation or derive_from"
            )
        key = representations[0]
        if key == "data_text":
            return str(value[key]).encode("utf-8")
        if key == "data_base64":
            return base64.b64decode(str(value[key]), validate=True)
        if key == "data_base64_parts":
            parts = value[key]
            if (
                not isinstance(parts, list)
                or not parts
                or not all(isinstance(part, str) for part in parts)
            ):
                raise ValueError("data_base64_parts must be a non-empty string list")
            return base64.b64decode("".join(parts), validate=True)
        if key == "data_hex":
            return bytes.fromhex(str(value[key]))
        path = (root / str(value[key])).resolve()
        if root not in path.parents and path != root:
            raise ValueError("fixture path escapes the calibration directory")
        return path.read_bytes()

    @staticmethod
    @contextmanager
    def _component_overrides(
        component: Any, case: Mapping[str, Any]
    ) -> "Iterator[None]":
        """Temporarily lower a component's configured bound for one case.

        A size-bound case has to make the component exceed its cap. With the
        shipped 50 MB defaults that would mean committing real decompression
        bombs and allocating 50 MB per case in CI. Shrinking the cap instead
        exercises the same code path with a few hundred bytes, and keeps the
        fixture readable.

        Only attributes the component already defines may be overridden, so a
        case cannot invent configuration that production never reads.
        """
        overrides = case.get("component_overrides") or {}
        if not overrides:
            yield
            return
        if not isinstance(overrides, Mapping):
            raise ValueError("component_overrides must be an object")
        previous: dict[str, Any] = {}
        for name, value in overrides.items():
            attribute = str(name)
            if not hasattr(component, attribute):
                raise ValueError(
                    f"component_overrides names an unknown attribute: {attribute}"
                )
            if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
                raise ValueError(
                    f"component_overrides['{attribute}'] must be a positive integer"
                )
            previous[attribute] = getattr(component, attribute)
        try:
            for attribute, value in overrides.items():
                setattr(component, str(attribute), value)
            yield
        finally:
            # The registry is shared across cases, so a leaked override would
            # silently change every later case's bounds.
            for attribute, value in previous.items():
                setattr(component, attribute, value)

    @staticmethod
    def _evaluate(
        kind: str,
        component: Any,
        data: bytes,
        case: Mapping[str, Any],
        *,
        evaluate_match: bool = True,
    ) -> tuple[bool, bool | None, dict[str, Any]]:
        if kind == "decoder":
            can_process = bool(component.can_decode(data))
            if not evaluate_match:
                return can_process, None, {"can_process": can_process}
            decoded = data
            success = False
            if can_process:
                decoded, success = component.decode(data)
            predicted = bool(can_process and success and decoded != data)
            expected_hash = str(case.get("expected_output_sha256") or "")
            output_hash = sha256(decoded).hexdigest() if predicted else None
            if expected_hash and output_hash != expected_hash:
                predicted = False
            # Size-bound cases assert the one property every amplifying
            # component shares, whatever shape its refusal takes: some decline
            # at recognition, some fail the decode, and some truncate to the
            # cap. Only a successful decode has output to bound.
            bound = case.get("expected_max_output_bytes")
            within_bound: bool | None = None
            if isinstance(bound, int) and bound > 0 and predicted:
                within_bound = len(decoded) <= bound
                if not within_bound:
                    predicted = False
            return (
                can_process,
                predicted,
                {
                    "can_process": can_process,
                    "output_sha256": output_hash,
                    "output_hash_matches": (
                        output_hash == expected_hash if expected_hash else None
                    ),
                    "output_bytes": len(decoded) if success else None,
                    "output_within_bound": within_bound,
                },
            )
        if kind == "analyzer":
            can_process = bool(component.can_analyze(data))
            if not evaluate_match:
                return can_process, None, {"can_process": can_process}
            artifacts = list(component.analyze(data)) if can_process else []
            names = sorted(str(name) for name, _ in artifacts)
            expected_names = {
                str(value) for value in case.get("expected_artifacts") or ()
            }
            predicted = bool(can_process and artifacts)
            if expected_names and not expected_names.issubset(names):
                predicted = False
            # An analyzer's ceiling covers everything it emits, including its
            # own summary record -- that was the gap: summaries were spliced
            # past the collector, so the declared total was not the real one.
            emitted = sum(len(content) for _name, content in artifacts)
            bound = case.get("expected_max_output_bytes")
            within_bound = None
            if isinstance(bound, int) and bound > 0:
                within_bound = emitted <= bound
                if not within_bound:
                    predicted = False
            return (
                can_process,
                predicted,
                {
                    "can_process": can_process,
                    "artifacts": names,
                    "expected_artifacts_present": (
                        expected_names.issubset(names) if expected_names else None
                    ),
                    "output_bytes": emitted,
                    "output_within_bound": within_bound,
                },
            )
        raise ValueError(f"unsupported calibration kind: {kind}")
