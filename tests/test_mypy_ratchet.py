"""The mypy exemption list must only shrink.

`[[tool.mypy.overrides]]` in pyproject.toml carries `ignore_errors = true` for
a list of modules, so type errors in them do not block merge. D5 of the
depth-hardening program removed them a group at a time, and the list is now
empty: every module in the package type-checks.

The list is the contract. These tests fail if an exemption is reintroduced, if
a module that has been cleaned goes back on the list, or if anything in the
package stops type-checking.
"""

import subprocess
import sys
import tomllib
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]

# The ratchet is empty: every module in the package type-checks. Adding an
# entry here is how a new exemption would be recorded, and doing so should be
# argued for rather than done quietly.
EXPECTED_EXEMPTIONS: dict[str, str] = {}


def _ratchet_list() -> set[str]:
    config = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    for override in config["tool"]["mypy"].get("overrides", []):
        if override.get("ignore_errors"):
            return set(override.get("module", []))
    return set()


def test_ratchet_list_matches_the_recorded_reasons():
    assert _ratchet_list() == set(EXPECTED_EXEMPTIONS), (
        "the mypy exemption list changed; record a reason in "
        "EXPECTED_EXEMPTIONS when an exemption is genuinely unavoidable, or "
        "remove the entry"
    )


@pytest.mark.parametrize(
    "module",
    [
        "titan_decoder.core.analyzers.base",
        "titan_decoder.core.correlation",
        "titan_decoder.core.engine",
        "titan_decoder.core.graph_export",
        "titan_decoder.core.ioc_export",
        "titan_decoder.core.vault",
        "titan_decoder.plugins",
    ],
)
def test_cleaned_modules_are_not_exempt_again(module):
    assert module not in _ratchet_list(), f"{module} was re-added to the ratchet"


def test_ratchet_is_empty():
    # The end state D5 was ratcheting towards. If this ever fails, the list
    # grew back and the reason belongs in EXPECTED_EXEMPTIONS.
    assert _ratchet_list() == set()


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
