# Releasing Titan Decoder (PyPI)

This doc is a practical checklist for publishing a new version of `titan-decoder` to PyPI.

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

## Release checklist

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
