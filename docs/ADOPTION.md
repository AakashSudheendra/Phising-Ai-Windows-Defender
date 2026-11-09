# Adoption And Showcase

This page gives teams a safe way to try PhishGuard AI and share public usage
evidence. The goal is practical adoption, not inflated activity.

## Quick CI Trial

Create a repository-owned file such as `.github/phishguard-urls.txt`:

```text
https://www.example.com/account
http://192.0.2.10/secure-login/verify
```

Use reserved documentation domains, internal test fixtures, or URLs your
organization owns. Do not commit credentials, private emails, customer data, or
live phishing infrastructure.

Then add this workflow:

```yaml
name: PhishGuard AI

on:
  pull_request:
  workflow_dispatch:

permissions:
  contents: read
  security-events: write

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Scan repository URL fixtures
        uses: omobolajiadeyan/phishguard-ai@v0.5.1
        with:
          urls-file: .github/phishguard-urls.txt
          sarif-output: phishguard-results.sarif
      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: phishguard-results.sarif
```

Pin the action to a release tag for repeatability. For stricter supply-chain
control, pin to a full commit SHA after reviewing the release source.

## Share A Usage Example

Open an adoption report issue when you have a public workflow, test result, or
write-up. Useful reports include:

- repository link;
- workflow file link;
- PhishGuard version;
- whether you used URL, email, JSON, or SARIF output;
- one safe example of what worked or what was confusing;
- whether the result should be listed publicly.

Maintainers may list public usage examples in `docs/PUBLIC_EVIDENCE.md` after
checking that the example is safe, verifiable, and not misleading.

## What Counts As Evidence

Strong adoption evidence:

- a third-party repository using the Marketplace Action;
- a public workflow run with safe fixtures;
- a technical write-up that includes commands, version, and limitations;
- a pull request or issue from an external user with reproducible feedback.

Weak or misleading evidence:

- mass forks with no usage;
- private screenshots that cannot be verified;
- claims based only on profile views;
- unsafe examples containing live phishing links or private data.

## Maintainer Promise

PhishGuard will keep public claims conservative. A project may be listed as a
usage example only when the evidence is visible and the integration is clear.
