# PhishGuard AI Use Cases

PhishGuard AI is best used as a lightweight, explainable signal in a broader
security workflow. It is not a replacement for enterprise email security,
threat intelligence feeds, or manual analyst judgment.

## 1. CI Check For Suspicious URLs

Use PhishGuard in GitHub Actions to scan URLs that appear in examples,
documentation, issue templates, or generated artifacts.

```yaml
- name: Scan URL with PhishGuard AI
  uses: omobolajiadeyan/phishguard-ai@v0.5.1
  with:
    url: http://192.0.2.10/secure-login/verify
    sarif-output: phishguard-results.sarif
```

Why this helps:

- produces an explainable result;
- can upload SARIF to GitHub Code Scanning;
- avoids sending repository content to a third-party phishing API.

## 2. SOC Triage Helper

Analysts can run a suspicious URL or email snippet locally and inspect the
feature breakdown.

```bash
phishguard url "http://192.0.2.10/secure-login/verify" --verbose --plain
```

This is useful for documenting why a URL looked suspicious before escalating
or closing a ticket. The output should be treated as supporting evidence, not
as a final verdict.

## 3. Email Authentication Experiments

PhishGuard can parse a trusted receiver's `Authentication-Results` header and
treat SPF, DKIM, and DMARC outcomes as supporting risk signals.

```bash
phishguard email \
  --subject "Security alert" \
  --body "Click here to verify your account." \
  --authentication-results "mx.example; spf=fail; dkim=fail; dmarc=fail" \
  --verbose \
  --plain
```

Important boundary:

- pass results do not make a message safe;
- failures are not automatic proof of phishing;
- callers must provide the final trusted receiver's header value.

For a saved message, name the receiver that produced the trusted result:

```bash
phishguard eml suspicious.eml \
  --trusted-authserv-id mx.example \
  --verbose
```

Without the option, embedded authentication headers are ignored. Matching is
exact and case-insensitive; it does not establish provenance by itself. The
receiving system must strip or neutralize forged headers that claim its own
authserv-id.

## 4. Security Education Demo

Because PhishGuard uses reserved domains and synthetic examples, it can be used
to teach phishing indicators without using live malicious infrastructure.

Suggested demo flow:

1. Scan a benign reserved-domain URL.
2. Scan a suspicious synthetic URL.
3. Compare the triggered features.
4. Export a JSON or SARIF result.
5. Discuss which signals are strong, weak, or context-dependent.

## 5. Regression Testing For Detection Ideas

Contributors can add public-safe examples and measure whether a scoring change
improves recall without increasing false positives.

```bash
python tools/evaluate_url_benchmark.py
python tools/evaluate_url_benchmark.py data/public_benchmark_urls.jsonl
python -m unittest discover -s tests -v
```

Good benchmark contributions include:

- clear expected labels;
- public-safe or synthetic inputs;
- before-and-after metrics;
- a short explanation of which feature or rule changed.

Do not add live phishing URLs, private emails, credentials, or personal data.

