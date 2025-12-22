# Releasing Titan Decoder (Preview + PyPI)

This doc is a practical checklist for:

- A **preview/beta** release shared via **GitHub only** (recommended for early community feedback)
- A later **PyPI** release (optional; do this when you want frictionless installs)

If you’re not publishing to PyPI yet, you still want a lightweight, repeatable way to point people to a specific snapshot (a tag/release). That’s what the “Preview (GitHub-only)” section is for.

## Preview (GitHub-only) — recommended for feedback

1. Pick a preview tag name

Examples:

- `v2.0.0-preview.1`
- `v2.0.0-beta.1`

2. (Optional) bump version if you want tags and `__version__` to match

Edit [titan_decoder/__init__.py](titan_decoder/__init__.py):

- `__version__ = "2.0.0"` (or `2.0.0b1` if you prefer)

3. Run tests

```bash
python -m pytest -q
```

Doc sync (recommended when behavior/options changed):

- Update examples and option descriptions in:
  - [README.md](README.md)
  - [docs/USAGE.md](docs/USAGE.md)
  - [docs/ANNOUNCEMENT.md](docs/ANNOUNCEMENT.md)

If the JSON report contract changed (new fields/sections), also update:

- [docs/report.schema.json](docs/report.schema.json)

4. Create and push the tag

```bash
git tag -a v2.0.0-preview.1 -m "Titan Decoder preview v2.0.0-preview.1"
git push origin v2.0.0-preview.1
```

5. Create a GitHub Release

On GitHub → Releases → “Draft a new release”:

- Tag: `v2.0.0-preview.1`
- Title: `Titan Decoder v2.0.0-preview.1 (Preview)`
- In the body, be explicit:
  - “Preview / feedback requested”
  - what you want feedback on (IOCs, false positives, decoders, UX)
  - that it’s not a hardened production tool yet

That’s enough to share widely and get feedback.

## One-time setup

1. Create accounts
- PyPI: https://pypi.org/
- (Recommended) TestPyPI: https://test.pypi.org/

2. Create an API token on PyPI (Account settings → API tokens)

3. Configure `~/.pypirc` (optional but convenient)

Example:

```ini
[pypi]
  username = __token__
  password = pypi-<YOUR_TOKEN>

[testpypi]
  repository = https://test.pypi.org/legacy/
  username = __token__
  password = pypi-<YOUR_TEST_TOKEN>
```

## PyPI release checklist (optional)

### 1) Pick the new version

Edit [titan_decoder/__init__.py](titan_decoder/__init__.py) and bump:

- `__version__ = "X.Y.Z"`

Use SemVer:
- Patch: bug fixes
- Minor: new features
- Major: breaking changes

### 2) Run tests locally

```bash
python -m pytest -q
```

### 3) Build distributions

Install build tooling:

```bash
python -m pip install -U build twine
```

Build:

```bash
python -m build
```

This creates:
- `dist/*.whl`
- `dist/*.tar.gz`

### 4) Check the package

```bash
twine check dist/*
```

### 5) (Recommended) Upload to TestPyPI first

```bash
twine upload -r testpypi dist/*
```

Test install from TestPyPI:

```bash
python -m pip install -i https://test.pypi.org/simple/ titan-decoder
```

### 6) Upload to PyPI

```bash
twine upload dist/*
```

### 7) Tag the release in git (recommended)

```bash
git tag -a vX.Y.Z -m "Titan Decoder vX.Y.Z"
git push origin vX.Y.Z
```

### 8) Create a GitHub Release

On GitHub → Releases → “Draft a new release”, pick the `vX.Y.Z` tag, paste highlights.

## Quick “release notes” template

- Added: …
- Fixed: …
- Changed: …
- Docs: …

## Common pitfalls

- If `pip install titan-decoder` works locally but not for users: verify you uploaded both sdist + wheel.
- If metadata looks wrong on PyPI: check `setup.py` fields and rerun `python -m build`.
- If a dependency is missing: add it to `install_requires` (core) or the `enrichment` extra.
