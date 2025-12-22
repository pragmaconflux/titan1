import json


def test_cli_offline_skips_enrichment_even_if_requested(tmp_path, monkeypatch):
    sample = tmp_path / "sample.txt"
    sample.write_text("http://example.com\n8.8.8.8\n")

    out = tmp_path / "report.json"

    # If enrichment were called, this would raise.
    import titan_decoder.core.enrichment as enrichment

    def _boom(*args, **kwargs):
        raise AssertionError("enrich_iocs should not be called in offline mode")

    monkeypatch.setattr(enrichment.EnrichmentEngine, "enrich_iocs", _boom)

    from titan_decoder import cli

    monkeypatch.setattr(
        "sys.argv",
        [
            "titan-decoder",
            "--file",
            str(sample),
            "--out",
            str(out),
            "--enable-enrichment",
            "--offline",
        ],
    )

    try:
        cli.main()
        assert False, "Expected SystemExit"
    except SystemExit as e:
        assert e.code == 0

    report = json.loads(out.read_text())
    assert report.get("meta", {}).get("offline") is True
    assert report.get("meta", {}).get("enrichment_requested") is True
    assert report.get("meta", {}).get("network_blocked") is True
    assert report.get("enrichment") is None
    assert report.get("meta", {}).get("enrichment_providers") == []
