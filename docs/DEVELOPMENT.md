# Development Workflow

This guide provides one reproducible path from a fresh clone to a reviewable
PhishGuard pull request.

## Local Setup

PhishGuard supports Python 3.10 through 3.13 and has no runtime dependencies.
Use a virtual environment so editable installs and build tools do not affect
the system Python installation.

```bash
git clone https://github.com/omobolajiadeyan/phishguard-ai.git
cd phishguard-ai
python -m venv .venv
```

Activate the environment:

```text
Windows:     .venv\Scripts\activate
macOS/Linux: source .venv/bin/activate
```

Install the project:

```bash
python -m pip install --upgrade pip
python -m pip install --editable .
phishguard --help
```

## Verification

Run the full unit suite:

```bash
python -m unittest discover -s tests -v
```

Run the repository security policy:

```bash
python tools/repository_policy.py
```

Review an unfamiliar pull-request diff before checking out or executing its
branch. Do not run contributed installers, binaries, or scripts outside an
isolated environment. CI jobs use read-only repository permissions, and
first-time contributor workflows require maintainer approval.

Compile every runtime module:

```bash
python -m py_compile \
  domain_age.py email_auth.py features.py model.py phishguard.py \
  psl.py redirect.py reporting.py server.py
```

When changing package metadata, installation, or release behavior, also run:

```bash
python -m pip install build twine
python -m build
python -m twine check dist/*
python -m pip install --force-reinstall dist/*.whl
phishguard url "https://example.com"
```

Remove generated `build/`, `dist/`, and `*.egg-info/` directories before
investigating a packaging result from scratch. These paths are ignored by Git.

## Test Data Safety

- Use `.example`, `.test`, `.invalid`, or `.localhost` for synthetic domains.
- Do not commit active phishing URLs, credentials, private email, or personal
  data.
- Add legitimate negative cases for every detection feature.
- State why each malicious-looking fixture is expected to trigger.
- Keep public-dataset licensing and provenance with any imported fixture.

## Pull Request Lifecycle

1. Comment on an open issue with the proposed behavior and tests.
2. Wait for maintainer confirmation before substantial implementation.
3. Create a focused branch and open a draft pull request when early feedback
   would reduce rework.
4. Add regression tests that demonstrate the intended behavior.
5. Run local verification and complete the pull request checklist.
6. Address review findings with focused commits.
7. Wait for Tests and CodeQL to pass before requesting final review.

One issue normally has one active implementation. Reviews, reproductions, test
ideas, and documentation feedback are welcome even when another contributor
owns the implementation.

## Architecture Boundaries

- `features.py` extracts named URL and email indicators.
- `email_auth.py` parses supplied email-authentication results.
- `model.py` applies reviewable heuristic weights and verdict thresholds.
- `phishguard.py` owns CLI parsing, display, and batch orchestration.
- `reporting.py` serializes native JSON and SARIF output.

Detection features should remain explainable. Serialization should consume
structured result data rather than re-read user-controlled input. CLI display
changes must not alter JSON or SARIF semantics unless the issue explicitly
changes those contracts.
