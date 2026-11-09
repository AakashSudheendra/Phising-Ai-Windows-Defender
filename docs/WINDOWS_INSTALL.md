# Windows Install Verification

This guide verifies the published PhishGuard AI release on Windows without
using live phishing infrastructure or external API keys.

## Requirements

- Windows PowerShell
- Python 3.10 through 3.13
- Internet access to download the release wheel from GitHub Releases
- GitHub CLI (`gh`) for optional release provenance verification

Check Python first:

```powershell
py --version
```

If the `py` launcher is not available, use `python --version` instead.

## Install In An Isolated Environment

Create and activate a virtual environment:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
```

If PowerShell blocks activation, run this command in the same terminal and try
activation again:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
```

Upgrade `pip` and install the verified release wheel:

```powershell
python -m pip install --upgrade pip
python -m pip install `
  https://github.com/omobolajiadeyan/phishguard-ai/releases/download/v0.5.1/phishguard_ai-0.5.1-py3-none-any.whl
```

## Verify The Command

Confirm the command is installed:

```powershell
phishguard --help
```

Run a safe URL example:

```powershell
phishguard url "https://example.com" --plain
```

Run a synthetic suspicious example. This uses a reserved test IP address, not a
live phishing site:

```powershell
phishguard url "http://192.0.2.10/secure-login/verify" --verbose --plain
```

Export SARIF for GitHub Code Scanning or CI review:

```powershell
phishguard url "http://192.0.2.10/secure-login/verify" `
  --format sarif `
  --output phishguard-results.sarif `
  --plain
```

Confirm the SARIF file was created:

```powershell
Test-Path .\phishguard-results.sarif
```

## Verify Release Provenance

Download the wheel from the release page, then verify its GitHub attestation
with GitHub CLI:

```powershell
gh attestation verify .\phishguard_ai-0.5.1-py3-none-any.whl `
  --repo omobolajiadeyan/phishguard-ai
```

## Cleanup

Deactivate the virtual environment when finished:

```powershell
deactivate
```

The virtual environment can be removed later by deleting the `.venv` directory.
