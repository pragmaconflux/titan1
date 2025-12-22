"""Detection rule packs (rules-as-data).

Rule packs let users extend detections without shipping new code.

Format (JSON or YAML):

schema_version: 1
pack:
  name: "Example Pack"
  version: "0.1.0"
rules:
  - id: "EX-001"
    name: "Contains powershell"
    description: "Detects PowerShell strings"
    severity: "medium"
    type: "content_regex"
    pattern: "powershell"
    flags: ["IGNORECASE"]

Supported rule types:
- content_regex: regex over concatenated node content_preview
- ioc_present: requires one or more IOC types to meet minimum counts
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional
import json
import re


@dataclass(frozen=True)
class RulePackInfo:
    name: str
    version: str
    schema_version: int
    path: str


class RulePackError(ValueError):
    pass


def load_rule_pack(path: Path) -> tuple[RulePackInfo, List[Dict[str, Any]]]:
    """Load a rule pack file (JSON or YAML)."""
    if not path.exists():
        raise RulePackError(f"Rule pack not found: {path}")

    raw: Dict[str, Any]
    suffix = path.suffix.lower()
    if suffix in {".json"}:
        raw = json.loads(path.read_text())
    elif suffix in {".yml", ".yaml"}:
        try:
            import yaml  # type: ignore
        except Exception as e:
            raise RulePackError(
                "YAML rule pack requires PyYAML (install via requirements-optional.txt)"
            ) from e
        raw = yaml.safe_load(path.read_text())
        if raw is None:
            raw = {}
    else:
        raise RulePackError(f"Unsupported rule pack type: {suffix}")

    if not isinstance(raw, dict):
        raise RulePackError("Rule pack root must be an object")

    schema_version = raw.get("schema_version", 1)
    if schema_version != 1:
        raise RulePackError(f"Unsupported rule pack schema_version: {schema_version}")

    pack = raw.get("pack") or {}
    if not isinstance(pack, dict):
        raise RulePackError("pack must be an object")

    name = str(pack.get("name") or "Unnamed Pack")
    version = str(pack.get("version") or "0.0.0")
    rules = raw.get("rules") or []
    if not isinstance(rules, list):
        raise RulePackError("rules must be an array")

    return RulePackInfo(
        name=name, version=version, schema_version=schema_version, path=str(path)
    ), rules


def compile_content_regex(pattern: str, flags: Optional[List[str]] = None) -> re.Pattern:
    re_flags = 0
    for f in flags or []:
        if f.upper() == "IGNORECASE":
            re_flags |= re.IGNORECASE
        elif f.upper() == "MULTILINE":
            re_flags |= re.MULTILINE
        elif f.upper() == "DOTALL":
            re_flags |= re.DOTALL
    return re.compile(pattern, re_flags)


def evaluate_pack_rule(
    rule_def: Dict[str, Any], report: Dict[str, Any], iocs: Dict[str, Any]
) -> bool:
    """Evaluate a single pack rule definition."""
    rtype = (rule_def.get("type") or "").strip()

    if rtype == "content_regex":
        pattern = rule_def.get("pattern")
        if not isinstance(pattern, str) or not pattern:
            return False
        flags = rule_def.get("flags")
        if flags is not None and not isinstance(flags, list):
            flags = None
        rx = compile_content_regex(pattern, flags)
        nodes = report.get("nodes", []) or []
        text = "\n".join((n.get("content_preview") or "") for n in nodes)
        return bool(rx.search(text))

    if rtype == "ioc_present":
        ioc_types = rule_def.get("ioc_types")
        if not isinstance(ioc_types, list) or not ioc_types:
            return False
        min_each = int(rule_def.get("min_each", 1))
        for t in ioc_types:
            values = iocs.get(str(t), []) or []
            if len(values) < min_each:
                return False
        return True

    # Unknown type
    return False
