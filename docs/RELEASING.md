# Releasing umbra-core

Releases publish to [PyPI](https://pypi.org/project/umbra-core/) automatically
via [`.github/workflows/release.yml`](.github/workflows/release.yml) when a
version tag is pushed. Publishing uses **PyPI Trusted Publishing (OIDC)** — no
API token is stored.

## One-time setup (per project, on PyPI)

1. Create the project owner account and sign in to PyPI.
2. Go to **Account → Publishing → Add a pending publisher** and register:
   - PyPI project name: `umbra-core`
   - Owner: `bkd-dotcom`
   - Repository name: `umbra-core`
   - Workflow name: `release.yml`
   - Environment name: `pypi`
3. In the GitHub repo, create an **Environment** named `pypi`
   (Settings → Environments). Optionally require a reviewer for the publish job.

## Cutting a release

1. Bump the version in [`pyproject.toml`](pyproject.toml) (`[project].version`).
2. Commit: `git commit -am "release: v0.1.0"`.
3. Tag and push:
   ```bash
   git tag v0.1.0
   git push origin main --tags
   ```
4. The `Release` workflow will:
   - verify the tag matches `pyproject.toml`,
   - run `ruff` + `pytest`,
   - build sdist + wheel and run `twine check`,
   - publish to PyPI via OIDC.

Verify locally before tagging:

```bash
uv build
uvx twine check dist/*
```

## Versioning

Semantic versioning. Until `1.0.0` the public API (the `umbra_core` top-level
exports, the `umbra` CLI, and the `run_admission` signature) may change between
minor versions; changes are noted in the release.
