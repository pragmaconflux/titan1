"""The mypy exemption list must only shrink.

`[[tool.mypy.overrides]]` in pyproject.toml carries `ignore_errors = true` for
a list of legacy modules, so type errors in them do not block merge. D5 of the
depth-hardening program removes them a group at a time; nothing may be added
back, and a module that has been cleaned must stay clean.

The list is the contract: these tests fail both when an exempt module is
silently reintroduced and when an exemption has become unnecessary and should
be dropped.
"""

import subprocess
import sys
import tomllib
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]

# Every module still exempt, with why it is not yet clean. Shrink this, never
# grow it.
EXPECTED_EXEMPTIONS = {
    "titan_decoder.core.analyzers.base": "archive member annotations and optional-return narrowing",
    "titan_decoder.core.correlation": "sqlite Connection is not narrowed before use",
    "titan_decoder.core.ioc_export": "optional returns and Sequence/list confusion",
    "titan_decoder.core.vault": "sqlite Connection is not narrowed before use",
}


def _ratchet_list() -> set[str]:
    config = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    for override in config["tool"]["mypy"].get("overrides", []):
        if override.get("ignore_errors"):
            return set(override.get("module", []))
    return set()


def test_ratchet_list_matches_the_recorded_reasons():
    assert _ratchet_list() == set(EXPECTED_EXEMPTIONS), (
        "the mypy exemption list changed; update EXPECTED_EXEMPTIONS with a "
        "reason when adding is genuinely unavoidable, or remove the entry"
    )


@pytest.mark.parametrize(
    "module",
    [
        "titan_decoder.core.engine",
        "titan_decoder.core.graph_export",
        "titan_decoder.plugins",
    ],
)
def test_cleaned_modules_are_not_exempt_again(module):
    assert module not in _ratchet_list(), f"{module} was re-added to the ratchet"


def test_package_type_checks_clean():
    # The exemptions above are the only tolerated type debt; everything else
    # must pass, or the gate is not really a gate.
    result = subprocess.run(
        [sys.executable, "-m", "mypy", "titan_decoder/"],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    errors = [line for line in result.stdout.splitlines() if ": error:" in line]
    assert not errors, "\n".join(errors)
