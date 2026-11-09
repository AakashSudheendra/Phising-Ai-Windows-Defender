# Email JSON and SARIF Examples

This example uses synthetic `.example` infrastructure and a supplied
`Authentication-Results` value. It is safe to reproduce offline.

## Generate the Reports

```bash
python phishguard.py email \
  --subject "Urgent: verify your payroll account" \
  --body "Review your account at http://secure-login.example/verify/account immediately." \
  --authentication-results "mx.example; spf=fail smtp.mailfrom=mailer.example; dkim=fail header.d=mailer.example; dmarc=fail header.from=mailer.example" \
  --format json \
  --output email-result.json \
  --plain

python phishguard.py email \
  --subject "Urgent: verify your payroll account" \
  --body "Review your account at http://secure-login.example/verify/account immediately." \
  --authentication-results "mx.example; spf=fail smtp.mailfrom=mailer.example; dkim=fail header.d=mailer.example; dmarc=fail header.from=mailer.example" \
  --format sarif \
  --output email-result.sarif \
  --plain
```

The current scoring model classifies this synthetic message as `PHISHING`
with probability `0.8134`.

## Native JSON

The native report contains the verdict, probability, and complete explainable
feature set. The authentication fields are shown below with enough surrounding
data to preserve valid JSON:

```json
{
  "subject": "Urgent: verify your payroll account",
  "verdict": "PHISHING",
  "probability": 0.8134,
  "features": {
    "url_count": 1,
    "urgency_word_count": 2,
    "word_count": 11,
    "spf_result": "fail",
    "dkim_result": "fail",
    "dmarc_result": "fail",
    "spf_auth_risk": 1.0,
    "dkim_auth_risk": 1.0,
    "dmarc_auth_risk": 1.0
  }
}
```

## SARIF 2.1.0 Finding

The corresponding SARIF result uses the phishing rule, error severity, a
human-readable message, and the same feature properties:

```json
{
  "ruleId": "PHISHGUARD_PHISHING",
  "level": "error",
  "message": {
    "text": "Email classified as PHISHING with 81.3% phishing risk."
  },
  "properties": {
    "probability": 0.8134,
    "targetType": "email",
    "features": {
      "url_count": 1,
      "urgency_word_count": 2,
      "word_count": 11,
      "spf_result": "fail",
      "dkim_result": "fail",
      "dmarc_result": "fail",
      "spf_auth_risk": 1.0,
      "dkim_auth_risk": 1.0,
      "dmarc_auth_risk": 1.0
    }
  }
}
```

The complete SARIF file also includes the SARIF 2.1.0 schema, tool and rule
metadata, a logical email location, and a stable partial fingerprint.

## Authentication Trust Boundary

PhishGuard parses the `Authentication-Results` value supplied by the caller.
It does not independently query DNS, validate SPF policy, verify a DKIM
signature, or evaluate DMARC alignment. Only pass a header produced by a
receiver you trust.

The `eml` command therefore ignores embedded `Authentication-Results` by
default. Use `--trusted-authserv-id mx.example` only when the receiving system
prevents untrusted messages from preserving or prepending a forged header with
that same authserv-id.

Authentication failures are supporting evidence, not proof of phishing.
Pass results do not reduce the risk score because authenticated infrastructure
can still deliver malicious content. Missing, malformed, and unsupported
values remain `unknown`.
