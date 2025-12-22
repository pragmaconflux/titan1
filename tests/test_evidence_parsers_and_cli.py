import json
from pathlib import Path

import pytest


def test_evidence_parser_dns_csv_produces_indicators(tmp_path: Path):
    from titan_decoder.core.evidence_parsers import parse_evidence_file

    dns = tmp_path / "dns.csv"
    dns.write_text(
        "timestamp,client_ip,query,answers\n"
        "2025-01-01 00:00:01,10.0.0.10,example.com,93.184.216.34\n"
    )

    res = parse_evidence_file(dns, "dns")
    assert len(res.events) == 1
    assert res.events[0].event_type == "dns_query"

    # Should include domain + answer IP + client IP
    vals = {(i.indicator_type, i.value) for i in res.indicators}
    assert ("domains", "example.com") in vals
    assert ("ipv4", "93.184.216.34") in vals
    assert ("ipv4", "10.0.0.10") in vals


def test_cli_evidence_attached_to_report(tmp_path: Path, monkeypatch):
    from titan_decoder import cli

    sample = tmp_path / "sample.txt"
    sample.write_text("hello http://example.com\n")

    dns = tmp_path / "dns.csv"
    dns.write_text(
        "timestamp,client_ip,query,answers\n"
        "2025-01-01 00:00:01,10.0.0.10,example.com,93.184.216.34\n"
    )

    out = tmp_path / "report.json"

    monkeypatch.setattr(
        "sys.argv",
        [
            "titan-decoder",
            "--file",
            str(sample),
            "--out",
            str(out),
            "--quiet",
            "--evidence",
            f"dns:{dns}",
        ],
    )

    try:
        cli.main()
        assert False, "Expected SystemExit"
    except SystemExit as e:
        assert e.code == 0

    report = json.loads(out.read_text())
    assert "evidence" in report
    assert "events" in report["evidence"]
    assert "indicators" in report["evidence"]
    assert len(report["evidence"]["events"]) == 1

    # Evidence pivots should exist
    assert "top_pivots" in report["evidence"]

    # Evidence links should exist
    assert "links" in report["evidence"]
    assert "top_links" in report["evidence"]
    assert isinstance(report["evidence"]["links"], list)


def test_cli_case_report_includes_evidence(tmp_path: Path, monkeypatch):
    from titan_decoder import cli

    sample = tmp_path / "sample.txt"
    sample.write_text("hello\n")

    proxy = tmp_path / "proxy.csv"
    proxy.write_text(
        "timestamp,src_ip,url,user_agent,user\n"
        "2025-01-01 00:00:02,10.0.0.10,http://example.com,UA-Test,alice\n"
    )

    report_out = tmp_path / "report.json"
    case_out = tmp_path / "case.md"

    monkeypatch.setattr(
        "sys.argv",
        [
            "titan-decoder",
            "--file",
            str(sample),
            "--out",
            str(report_out),
            "--report-out",
            str(case_out),
            "--report-format",
            "markdown",
            "--quiet",
            "--evidence",
            f"proxy:{proxy}",
        ],
    )

    try:
        cli.main()
        assert False, "Expected SystemExit"
    except SystemExit as e:
        assert e.code == 0

    md = case_out.read_text()
    assert "Evidence (Normalized)" in md
    assert "Top Pivots" in md
    assert "Top Links" in md


def test_evidence_parser_powershell_history(tmp_path: Path):
    from titan_decoder.core.evidence_parsers import parse_evidence_file

    ps = tmp_path / "ConsoleHost_history.txt"
    ps.write_text("Invoke-WebRequest http://example.com\n")

    res = parse_evidence_file(ps, "powershell_history")
    assert any(e.event_type == "powershell_command" for e in res.events)
    vals = {(i.indicator_type, i.value) for i in res.indicators}
    assert ("urls", "http://example.com") in vals


def test_evidence_timeline_export_from_evidence_events(tmp_path: Path, monkeypatch):
    from titan_decoder import cli

    sample = tmp_path / "sample.txt"
    sample.write_text("hello\n")

    proxy = tmp_path / "proxy.csv"
    proxy.write_text(
        "timestamp,src_ip,url,user_agent,user\n"
        "2025-01-01 00:00:02,10.0.0.10,http://example.com,UA-Test,alice\n"
    )

    report_out = tmp_path / "report.json"
    ev_tl = tmp_path / "evidence_timeline.csv"

    monkeypatch.setattr(
        "sys.argv",
        [
            "titan-decoder",
            "--file",
            str(sample),
            "--out",
            str(report_out),
            "--quiet",
            "--evidence",
            f"proxy:{proxy}",
            "--evidence-timeline-out",
            str(ev_tl),
            "--evidence-timeline-format",
            "csv",
        ],
    )

    try:
        cli.main()
        assert False, "Expected SystemExit"
    except SystemExit as e:
        assert e.code == 0

    content = ev_tl.read_text()
    assert "event_type" in content
    assert "proxy_request" in content
