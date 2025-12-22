import json


def test_cli_fail_on_risk_level_high_exits_nonzero(tmp_path, monkeypatch):
    # Use a payload that triggers at least one HIGH detection.
    # TITAN-003 (LOLBin Script Execution Pattern) is severity=medium, so instead
    # we include a URL + public IP + OLE marker? That's too heavy.
    # The simplest reliable path is XOR+C2 (high) may vary, so we trigger
    # Multi-Stage Infrastructure (high) by including urls + ipv4 + domains + emails.
    data = (
        b"http://example.com\n"
        b"8.8.8.8\n"
        b"example.org\n"
        b"test@example.org\n"
    )

    sample = tmp_path / "sample.txt"
    sample.write_bytes(data)
    out = tmp_path / "report.json"

    from titan_decoder import cli

    monkeypatch.setattr(
        "sys.argv",
        [
            "titan-decoder",
            "--file",
            str(sample),
            "--out",
            str(out),
            "--enable-detections",
            "--fail-on-risk-level",
            "HIGH",
        ],
    )

    try:
        cli.main()
        assert False, "Expected SystemExit"
    except SystemExit as e:
        assert e.code == 2

    report = json.loads(out.read_text())
    assert "risk_assessment" in report
    assert report["risk_assessment"]["risk_level"] in {"HIGH", "CRITICAL"}


def test_cli_fail_on_risk_level_high_allows_clean(tmp_path, monkeypatch):
    # A benign payload with no IOCs.
    data = b"just some harmless text\n"
    sample = tmp_path / "sample.txt"
    sample.write_bytes(data)
    out = tmp_path / "report.json"

    from titan_decoder import cli

    monkeypatch.setattr(
        "sys.argv",
        [
            "titan-decoder",
            "--file",
            str(sample),
            "--out",
            str(out),
            "--enable-detections",
            "--fail-on-risk-level",
            "HIGH",
        ],
    )

    try:
        cli.main()
        assert False, "Expected SystemExit"
    except SystemExit as e:
        assert e.code == 0
