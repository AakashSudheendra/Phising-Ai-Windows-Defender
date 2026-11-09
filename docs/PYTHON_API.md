# Python API Guide

PhishGuard AI can be embedded directly in Python code when a CLI subprocess is
not the right fit. The current public API is intentionally small:

- `model.score_url(url, extra_features=None)`
- `model.score_email(subject, body, authentication_results=None)`
- `model.classify(probability)`

The API returns explainable heuristic scores. The probability value is a
bounded risk score, not a calibrated statistical probability from a trained
model.

## URL Scoring

```python
from model import classify, score_url

probability, features = score_url("https://www.example.com/account")

assert 0.0 <= probability <= 1.0
assert classify(probability) == "SAFE"
assert "has_ip_address" in features
```

`score_url()` returns a tuple:

1. `probability`: a rounded float from `0.0` to `1.0`.
2. `features`: a dictionary of extracted URL signals used by the heuristic
   model.

Callers that already collected redirect-chain evidence can pass
`extra_features`:

```python
from model import classify, score_url

probability, features = score_url(
    "https://www.example.com/login",
    extra_features={
        "redirect_hops": 2,
        "redirect_crossed_domain": 1,
    },
)

assert features["redirect_hops"] == 2
assert classify(probability) in {"SAFE", "SUSPICIOUS", "PHISHING"}
```

## Email Scoring

```python
from model import classify, score_email

probability, features = score_email(
    "Security alert",
    "Click here to verify your account.",
    "mx.example; spf=fail; dkim=fail; dmarc=fail",
)

assert classify(probability) == "PHISHING"
assert features["dmarc_result"] == "fail"
```

`authentication_results` should come from a trusted receiving system's
`Authentication-Results` header. SPF, DKIM, and DMARC failures are treated as
supporting evidence. Pass results do not reduce risk because authenticated
infrastructure can still send malicious content.

## Verdicts

Use `classify(probability)` to convert a score into a stable verdict string:

| Score Range | Verdict |
| --- | --- |
| `>= 0.75` | `PHISHING` |
| `>= 0.55` and `< 0.75` | `SUSPICIOUS` |
| `< 0.55` | `SAFE` |

The numeric thresholds are part of the current heuristic model and may evolve
between minor versions. Pin a release version in production workflows when
repeatability matters.

## Stability Notes

- `score_url`, `score_email`, and `classify` are the supported import surface
  for the current release line.
- Feature dictionary keys are documented model evidence, but new keys may be
  added as detection coverage improves.
- Existing keys should not be removed without a release note.
- The CLI remains the most stable integration path for shell and CI workflows.

## Verification

The examples in this guide are covered by
`tests/test_public_api_docs.py`.
