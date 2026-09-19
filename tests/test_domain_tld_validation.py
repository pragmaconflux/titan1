"""Domain IOCs must end in a real TLD.

The domain regex matches any dotted token, so before TLD validation it
reported JavaScript member access ("WScript.Shell"), COM ProgIDs
("ADODB.Stream"), and labels fused to adjacent binary ("payload.binPK" from a
ZIP central directory) as domain indicators. Those fed risk scoring, the
intelligence signal counts, and cross-case infrastructure correlation, so the
noise did not stay contained in the IOC list.
"""

import pytest

from titan_decoder.utils import helpers
from titan_decoder.utils.helpers import extract_iocs, is_known_tld, known_tlds


def _domains(text: str) -> list[str]:
    return extract_iocs(text)["domains"]


def test_tld_snapshot_loads():
    tlds = known_tlds()
    # The IANA root zone carries well over a thousand delegated TLDs; a much
    # smaller number means the snapshot failed to parse.
    assert len(tlds) > 1000
    assert {"com", "net", "org", "co", "io"} <= tlds


def test_rfc_reserved_names_are_recognized():
    # Not delegated, so absent from IANA's file, but they appear in real
    # evidence -- .onion especially -- and throughout Titan's own fixtures.
    for label in ("example", "invalid", "local", "localhost", "onion", "test"):
        assert is_known_tld(label), label


@pytest.mark.parametrize(
    "text",
    [
        'var s = WScript.CreateObject("WScript.Shell")',
        "$stream = New-Object ADODB.Stream",
        "Scripting.FileSystemObject",
        "MSXML2.XMLHTTP",
        "obj.Method.Nonsense",
        "payload.binPK\x01\x02dropper.jsPK",
        "LoadLibrary(kernel32.dll)",
    ],
)
def test_code_and_binary_artifacts_are_not_domains(text):
    assert _domains(text) == []


@pytest.mark.parametrize(
    "domain",
    [
        "evil-c2.example.net",
        "beacon.test",
        "hidden.onion",
        "shop.zip",
        "acme.shell",
        "update.microsoft.com",
        "host.co.uk",
    ],
)
def test_real_domains_are_preserved(domain):
    assert domain in _domains(f"contacting {domain} now")


def test_object_prefix_filter_does_not_drop_ordinary_domains():
    # "acme.shell" must survive even though "wscript.shell" does not: the
    # filter keys on the leading label, not on the (genuinely delegated) TLD.
    text = "wscript.shell and acme.shell"
    assert _domains(text) == ["acme.shell"]


def test_unreadable_snapshot_fails_open(monkeypatch):
    # Losing the data file must not silently delete every domain indicator
    # from a report; validation failure falls back to the denylist rules.
    known_tlds.cache_clear()
    monkeypatch.setattr(helpers, "_TLD_DATA_FILE", helpers.Path("/nonexistent/tlds"))
    try:
        assert known_tlds() == frozenset()
        assert is_known_tld("madeuptld")
        assert "host.madeuptld" in _domains("see host.madeuptld")
    finally:
        known_tlds.cache_clear()


def test_snapshot_is_reloaded_after_cache_clear():
    known_tlds.cache_clear()
    assert is_known_tld("com")
