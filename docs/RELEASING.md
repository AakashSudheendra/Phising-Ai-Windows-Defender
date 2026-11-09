# Release Process

PhishGuard releases are built from Git tags by
`.github/workflows/release.yml`. The workflow builds the source distribution
and wheel on GitHub-hosted infrastructure rather than uploading artifacts
built on a maintainer workstation.

## Prepare

1. Merge only changes with passing Tests and CodeQL workflows.
2. Move relevant entries from `Unreleased` to a dated changelog section.
3. Replace the development version in `pyproject.toml` with the release
   version.
4. Run:

   ```bash
   python -m unittest discover -s tests -v
   python -m build
   python -m twine check dist/*
   ```

5. Commit the release metadata and create a matching tag, such as `v0.4.0`.

The release workflow fails when the tag without its leading `v` does not
exactly match the package version.

For PyPI preparation, see [PYPI_PUBLISHING.md](PYPI_PUBLISHING.md). PyPI upload
should use Trusted Publishing rather than a long-lived API token.

For a Marketplace release, open the root `action.yml` on GitHub and use its
**Draft a release** banner. Select **Publish this Action to the GitHub
Marketplace** before publishing the release. Creating a release through the
CLI alone does not select the Marketplace listing option.

## Published Evidence

For a valid release tag, GitHub Actions publishes:

- A Python wheel
- A source distribution
- A `SHA256SUMS` file
- A signed build-provenance attestation

Consumers can verify a downloaded artifact with GitHub CLI:

```bash
gh attestation verify phishguard_ai-0.4.0-py3-none-any.whl \
  --repo omobolajiadeyan/phishguard-ai
```

The workflow can also be started manually to test the build and installation
steps. Manual runs do not create releases or attestations.
