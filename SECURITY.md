# Security Policy

## Reporting a Vulnerability

Please do not open a public issue for a vulnerability that could put users or
their data at risk. Use GitHub's
[private vulnerability reporting form](https://github.com/omobolajiadeyan/phishguard-ai/security/advisories/new)
so the report and follow-up remain confidential.

If GitHub private reporting is unavailable, email
[omobolaji.adeyan@gmail.com](mailto:omobolaji.adeyan@gmail.com). Include:

- A concise description of the issue and its impact.
- Reproduction steps or a proof of concept using synthetic data.
- The affected commit or version.
- Any suggested mitigation.

You should receive an acknowledgement within three business days. Confirmed
reports will be assessed for impact, affected versions, remediation, and
coordinated disclosure. Please allow time for a fix before publishing details.

Public issues are appropriate for detection accuracy, false positives, false
negatives that do not expose sensitive data, and general hardening proposals.

## Scope

Security reports may cover URL and email parsing, JSON export, CLI input
handling, dependency or workflow security, and unsafe handling of test data.

PhishGuard is an educational, heuristic detection tool. Its verdicts should be
treated as decision support, not as a replacement for browser protections,
email authentication, threat intelligence, or analyst review.
