# Contributing to PhishGuard AI

Thank you for helping improve PhishGuard. Contributions should make detection
more accurate, explainable, portable, or easier to verify.

## Development Setup

PhishGuard uses only the Python standard library.

```bash
git clone https://github.com/omobolajiadeyan/phishguard-ai.git
cd phishguard-ai
python -m venv .venv
# Windows: .venv\Scripts\activate
# macOS/Linux: source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install --editable .
python -m unittest discover -s tests -v
phishguard --help
```

Python 3.10 or newer is supported.
The complete local verification and pull-request workflow is documented in
[docs/DEVELOPMENT.md](docs/DEVELOPMENT.md).

First-time contributors can use the shorter
[first-contribution guide](docs/FIRST_CONTRIBUTION.md) and choose an unclaimed
issue labeled
[`good first issue`](https://github.com/omobolajiadeyan/phishguard-ai/issues?q=is%3Aissue%20state%3Aopen%20label%3A%22good%20first%20issue%22).

## Good Contributions

- Add labeled legitimate and phishing samples with a source and rationale.
- Reduce false positives without weakening existing malicious test cases.
- Add explainable URL or email features with focused unit tests.
- Improve cross-platform CLI behavior.
- Improve documentation when it is tied to verified behavior.

Do not include live credentials, private email, personal data, or active
phishing payloads. Use reserved domains and clearly synthetic samples in tests.

Do not include executables, compiled binaries, symbolic links, obfuscated
payloads, download-and-execute scripts, or unexpected dependencies. Repository
policy checks reject these automatically. A maintainer must inspect the diff
before running code from an unfamiliar fork; passing CI is supporting evidence,
not proof that a contribution is safe.

## Pull Requests

1. Open or reference an issue describing the behavior.
2. Comment on the issue and wait for a maintainer to confirm the approach
   before starting substantial work. This avoids duplicate pull requests.
3. Keep the change focused. Draft pull requests are welcome for early feedback.
4. Add tests that fail before the change and pass afterward.
5. Run `python -m unittest discover -s tests -v`.
6. Run `python tools/repository_policy.py`.
7. Explain any scoring or threshold change with before-and-after examples.
8. Update user-facing documentation when commands, output, or features change.

An issue normally has one active implementation. You can still contribute by
reviewing an open pull request, reproducing the behavior, suggesting test
cases, or choosing another unclaimed issue.

Detection changes should include both positive and negative samples. A model
change that catches more phishing but labels common legitimate sites as
malicious is a regression.

## Review and Credit

Maintainers review correctness, false-positive impact, test quality, security,
scope, and documentation. Passing CI is required but does not replace review.

Accepted contributors are credited in [AUTHORS.md](AUTHORS.md) after their
first merged contribution. Code, tests, documentation, issue triage, and
technically grounded review are all meaningful contributions.

Testing an open pull request is especially useful. Report the operating
system, Python version, exact command, observed result, and whether the result
matches the pull request description.
