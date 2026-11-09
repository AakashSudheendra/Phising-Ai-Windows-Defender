# Your First PhishGuard Contribution

This guide is the shortest path from a fresh clone to a reviewable pull
request. Code is welcome, but documentation, testing, research, and
technically grounded review are also meaningful contributions.

## Choose Work

Start with an unclaimed issue labeled
[`good first issue`](https://github.com/omobolajiadeyan/phishguard-ai/issues?q=is%3Aissue%20state%3Aopen%20label%3A%22good%20first%20issue%22).
Comment on the issue with:

1. The behavior you plan to change.
2. The files you expect to touch.
3. The tests or checks you will run.

Wait for maintainer confirmation before substantial implementation. This
prevents two contributors from doing the same work.

## Set Up

```bash
git clone https://github.com/omobolajiadeyan/phishguard-ai.git
cd phishguard-ai
python -m venv .venv
```

Activate the environment and install the project:

```text
Windows:     .venv\Scripts\activate
macOS/Linux: source .venv/bin/activate
```

```bash
python -m pip install --editable .
python -m unittest discover -s tests -v
python tools/repository_policy.py
```

## Make a Focused Change

- Use synthetic data and reserved domains such as `.example`.
- Add a legitimate negative case for every new detection signal.
- Do not add credentials, personal email, live phishing payloads, binaries,
  symbolic links, or unexpected dependencies.
- Update documentation when user-facing behavior changes.

## Open the Pull Request

Complete the pull request checklist and include:

- A concise explanation of the problem and solution.
- A link to the confirmed issue.
- Exact verification commands and results.
- Before-and-after scores for detection changes.
- Any known limitations or false-positive tradeoffs.

Accepted contributors are credited in `AUTHORS.md` after their first merged
contribution.

## Contribute Without Writing a Feature

You can still make a useful contribution by:

- Testing an open pull request and reporting the command, platform, and result.
- Reproducing a bug with a public-safe fixture.
- Reviewing documentation for commands that do not work as written.
- Researching a benchmark source and documenting its license and provenance.
- Suggesting legitimate negative cases for an existing detector.

Use
[GitHub Discussions](https://github.com/omobolajiadeyan/phishguard-ai/discussions)
for questions and early design ideas.
