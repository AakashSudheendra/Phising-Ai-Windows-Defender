# PyPI Publishing Plan

Publishing PhishGuard AI to PyPI would make adoption easier because users could
install it with:

```bash
python -m pip install phishguard-ai
```

This document tracks the safe path to that milestone. It intentionally avoids
password-based publishing and long-lived API tokens.

## Recommended Approach

Use PyPI Trusted Publishing from GitHub Actions.

Benefits:

- no PyPI token stored in GitHub secrets;
- release provenance is tied to GitHub Actions;
- publishing can be limited to tagged releases;
- the existing release workflow already builds and validates the wheel.

## Preconditions

1. Create or claim the `phishguard-ai` project on PyPI.
2. Configure PyPI Trusted Publishing for this repository:
   - owner: `omobolajiadeyan`
   - repository: `phishguard-ai`
   - workflow: `.github/workflows/release.yml`
   - environment: `pypi`
3. Confirm the package metadata:
   - project name: `phishguard-ai`
   - console command: `phishguard`
   - supported Python versions: 3.10 through 3.13
   - license: MIT
4. Publish a test release to TestPyPI before publishing to PyPI.

## GitHub Workflow Status

The release workflow is prepared for Trusted Publishing:

- tagged releases build and validate the wheel and source distribution;
- build artifacts are uploaded for GitHub Releases;
- a separate PyPI artifact includes only `*.whl` and `*.tar.gz` files so
  `SHA256SUMS` is not passed to the PyPI upload action;
- the `publish-pypi` job runs only for `v*` tags;
- the publish job uses the protected `pypi` environment;
- publishing uses OpenID Connect (`id-token: write`) instead of a stored PyPI
  token.

Before the first production publish, create a GitHub environment named `pypi`
and add manual approval protection. Then configure the matching Trusted
Publisher on PyPI.

## Release Checklist

Before enabling PyPI upload for a production tag:

```bash
python -m unittest discover -s tests -v
python -m build
python -m twine check dist/*
python -m pip install --force-reinstall dist/*.whl
phishguard --help
phishguard url "https://example.com"
```

After publishing to TestPyPI:

```bash
python -m pip install \
  --index-url https://test.pypi.org/simple/ \
  --extra-index-url https://pypi.org/simple/ \
  phishguard-ai
phishguard --help
```

After publishing to PyPI:

```bash
python -m pip install phishguard-ai
phishguard --help
```

## Documentation Updates After Publishing

Once the package is available on PyPI:

1. Update the README installation section to prefer:

   ```bash
   python -m pip install phishguard-ai
   ```

2. Keep GitHub Release wheel installation as the reproducible fallback.
3. Add a PyPI badge near the release badge.
4. Add the PyPI project URL to `pyproject.toml` under `[project.urls]`.
5. Mention the PyPI package in the next changelog entry.

## Safety Notes

- Do not publish from a local workstation.
- Do not store a long-lived PyPI API token in the repository.
- Do not publish a tag unless Tests, CodeQL, repository policy, package build,
  and wheel-installation checks pass.
- Do not reuse a version number. PyPI versions are immutable after upload.
