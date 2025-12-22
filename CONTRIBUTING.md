# Contributing

Thanks for your interest in improving Titan Decoder.

## Ground Rules

- Keep changes **dependency-light** by default.
- Preserve **offline-first** behavior and deterministic outputs.
- Do not submit real incident evidence (logs, browser history DBs, reports) in issues or PRs.

## Development

```bash
python -m venv .venv
. .venv/bin/activate
pip install -e '.[dev]'
pytest -q
```

## Pull Requests

- Include tests for new behavior when practical.
- Update docs if flags/output contracts change.
- Keep PRs focused; avoid drive-by refactors.
