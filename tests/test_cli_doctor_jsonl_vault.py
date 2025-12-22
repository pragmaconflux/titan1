import json
from pathlib import Path


def test_cli_doctor_outputs_json_and_exits_zero(monkeypatch, capsys):
    from titan_decoder import cli

    monkeypatch.setattr("sys.argv", ["titan-decoder", "--doctor"])

    try:
        cli.main()
        assert False, "Expected SystemExit"
    except SystemExit as e:
        assert e.code == 0

    out = capsys.readouterr().out
    diag = json.loads(out)
    assert diag["ok"] is True
    assert "python" in diag
    assert "optional_dependencies" in diag
    assert "version" in diag
    assert "schema_version" in diag


def test_cli_version_flag_prints_version(monkeypatch, capsys):
    from titan_decoder import cli
    from titan_decoder import __version__

    monkeypatch.setattr("sys.argv", ["titan-decoder", "--version"])

    try:
        cli.main()
        assert False, "Expected SystemExit"
    except SystemExit as e:
        assert e.code == 0

    out = capsys.readouterr().out
    assert __version__ in out


def test_cli_print_schema_version(monkeypatch, capsys):
    from titan_decoder import cli
    from titan_decoder.core.engine import SCHEMA_VERSION

    monkeypatch.setattr("sys.argv", ["titan-decoder", "--print-schema-version"])

    try:
        cli.main()
        assert False, "Expected SystemExit"
    except SystemExit as e:
        assert e.code == 0

    out = capsys.readouterr().out
    payload = json.loads(out)
    assert payload["schema_version"] == SCHEMA_VERSION


def test_cli_list_decoders(monkeypatch, capsys, tmp_path):
    from titan_decoder import cli

    # Use default config; just ensure output is valid JSON with decoders.
    monkeypatch.setattr("sys.argv", ["titan-decoder", "--list-decoders"])

    try:
        cli.main()
        assert False, "Expected SystemExit"
    except SystemExit as e:
        assert e.code == 0

    out = capsys.readouterr().out
    payload = json.loads(out)
    assert "decoders" in payload
    assert isinstance(payload["decoders"], list)
    assert any(d.get("name") == "Base64" for d in payload["decoders"])


def test_cli_rules_validate_good_pack(tmp_path, monkeypatch, capsys):
    pack = tmp_path / "pack.json"
    pack.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "pack": {"name": "T", "version": "0.1.0"},
                "rules": [
                    {
                        "id": "T-1",
                        "name": "Has URL",
                        "description": "d",
                        "severity": "low",
                        "type": "ioc_present",
                        "ioc_types": ["urls"],
                        "min_each": 1,
                    }
                ],
            }
        )
    )

    from titan_decoder import cli

    monkeypatch.setattr("sys.argv", ["titan-decoder", "--rules-validate", str(pack)])

    try:
        cli.main()
        assert False, "Expected SystemExit"
    except SystemExit as e:
        assert e.code == 0

    out = capsys.readouterr().out
    payload = json.loads(out)
    assert payload["ok"] is True
    assert payload["results"][0]["ok"] is True


def test_cli_stdout_none_suppresses_stdout(tmp_path, monkeypatch, capsys):
    sample = tmp_path / "sample.txt"
    sample.write_text("hello\n")

    from titan_decoder import cli

    monkeypatch.setattr(
        "sys.argv",
        [
            "titan-decoder",
            "--file",
            str(sample),
            "--stdout",
            "none",
            "--quiet",
        ],
    )

    try:
        cli.main()
        assert False, "Expected SystemExit"
    except SystemExit as e:
        assert e.code == 0

    out = capsys.readouterr().out
    assert out.strip() == ""


def test_cli_strict_mode_fails_on_invalid_report(tmp_path, monkeypatch, capsys):
    sample = tmp_path / "sample.txt"
    sample.write_text("hello\n")

    from titan_decoder import cli

    def _bad_report(self, data):
        return {"meta": {}, "node_count": 0, "nodes": [], "iocs": {}}

    monkeypatch.setattr(cli.TitanEngine, "run_analysis", _bad_report)

    monkeypatch.setattr(
        "sys.argv",
        [
            "titan-decoder",
            "--file",
            str(sample),
            "--strict",
            "--stdout",
            "none",
            "--quiet",
        ],
    )

    try:
        cli.main()
        assert False, "Expected SystemExit"
    except SystemExit as e:
        assert e.code == 1


def test_cli_max_report_size_mb_enforced(tmp_path, monkeypatch):
    sample = tmp_path / "sample.txt"
    sample.write_text("hello\n")

    out = tmp_path / "report.json"

    from titan_decoder import cli

    # Extremely tiny limit to force failure.
    monkeypatch.setattr(
        "sys.argv",
        [
            "titan-decoder",
            "--file",
            str(sample),
            "--out",
            str(out),
            "--max-report-size-mb",
            "0.000001",
            "--quiet",
        ],
    )

    try:
        cli.main()
        assert False, "Expected SystemExit"
    except SystemExit as e:
        assert e.code == 1


def test_cli_jsonl_out_writes_events(tmp_path, monkeypatch):
    sample = tmp_path / "sample.txt"
    sample.write_text("http://example.com\n8.8.8.8\n")

    out = tmp_path / "report.json"
    jsonl = tmp_path / "events.jsonl"

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
            "--jsonl-out",
            str(jsonl),
            "--quiet",
        ],
    )

    try:
        cli.main()
        assert False, "Expected SystemExit"
    except SystemExit as e:
        assert e.code == 0

    assert out.exists()
    assert jsonl.exists()

    lines = [ln for ln in jsonl.read_text().splitlines() if ln.strip()]
    assert len(lines) >= 3
    first = json.loads(lines[0])
    assert first["type"] == "meta"


def test_cli_vault_store_and_search(tmp_path, monkeypatch, capsys):
    sample = tmp_path / "sample.txt"
    sample.write_text("http://example.com\n")

    vault_dir = tmp_path / "vault"
    db_path = vault_dir / "vault.db"

    # Point config at the temp vault.
    cfg = tmp_path / "config.json"
    cfg.write_text(
        json.dumps(
            {
                "vault_dir": str(vault_dir),
                "vault_db_path": str(db_path),
            }
        )
    )

    out = tmp_path / "report.json"

    from titan_decoder import cli

    # Store a run.
    monkeypatch.setattr(
        "sys.argv",
        [
            "titan-decoder",
            "--file",
            str(sample),
            "--out",
            str(out),
            "--config",
            str(cfg),
            "--vault-store",
            "--quiet",
        ],
    )

    try:
        cli.main()
        assert False, "Expected SystemExit"
    except SystemExit as e:
        assert e.code == 0

    assert db_path.exists()

    report = json.loads(out.read_text())
    analysis_id = report.get("meta", {}).get("analysis_id")
    assert analysis_id

    stored_report = vault_dir / f"{analysis_id}.json"
    assert stored_report.exists()

    # Search for the URL.
    monkeypatch.setattr(
        "sys.argv",
        [
            "titan-decoder",
            "--config",
            str(cfg),
            "--vault-search",
            "http://example.com",
        ],
    )

    try:
        cli.main()
        assert False, "Expected SystemExit"
    except SystemExit as e:
        assert e.code == 0

    stdout = capsys.readouterr().out
    result = json.loads(stdout)
    assert result["query"] == "http://example.com"
    assert len(result["matches"]) >= 1
    assert any(m.get("analysis_id") == analysis_id for m in result["matches"])


def test_cli_vault_list_recent_and_search_type(tmp_path, monkeypatch, capsys):
    sample = tmp_path / "sample.txt"
    sample.write_text("http://example.com\n")

    vault_dir = tmp_path / "vault"
    db_path = vault_dir / "vault.db"

    cfg = tmp_path / "config.json"
    cfg.write_text(
        json.dumps(
            {
                "vault_dir": str(vault_dir),
                "vault_db_path": str(db_path),
            }
        )
    )

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
            "--config",
            str(cfg),
            "--vault-store",
            "--quiet",
        ],
    )

    try:
        cli.main()
        assert False, "Expected SystemExit"
    except SystemExit as e:
        assert e.code == 0

    # List recent
    monkeypatch.setattr(
        "sys.argv",
        [
            "titan-decoder",
            "--config",
            str(cfg),
            "--vault-list-recent",
            "10",
        ],
    )

    try:
        cli.main()
        assert False, "Expected SystemExit"
    except SystemExit as e:
        assert e.code == 0

    payload = json.loads(capsys.readouterr().out)
    assert "recent" in payload
    assert len(payload["recent"]) >= 1

    # Type-filter search
    monkeypatch.setattr(
        "sys.argv",
        [
            "titan-decoder",
            "--config",
            str(cfg),
            "--vault-search",
            "http://example.com",
            "--vault-search-type",
            "urls",
        ],
    )

    try:
        cli.main()
        assert False, "Expected SystemExit"
    except SystemExit as e:
        assert e.code == 0

    result = json.loads(capsys.readouterr().out)
    assert result["query"] == "http://example.com"
    assert len(result["matches"]) >= 1
