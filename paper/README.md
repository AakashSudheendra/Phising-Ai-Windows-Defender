# IEEE Paper: PhishGuard Defender

IEEE conference paper (IEEEtran, two-column) describing the Windows desktop
protection center, Manifest V3 browser extension, and local security service.

| File | Purpose |
| --- | --- |
| `main.tex` | Paper source. The figure is drawn in TikZ, so no image files are needed |
| `references.bib` | 26 references in BibTeX (IEEEtran style) |
| `phishguard-defender-ieee-overleaf.zip` | Upload-ready Overleaf bundle |

## Open in Overleaf

1. Go to <https://www.overleaf.com> → **New Project** → **Upload Project**.
2. Select `phishguard-defender-ieee-overleaf.zip`.
3. Compiler: **pdfLaTeX** (Menu → Settings). Main document: `main.tex`.
4. Click **Recompile**. Overleaf runs BibTeX automatically.

## Before submitting

- Replace the three placeholder authors in the `\author{...}` block of `main.tex`.
- Update the measurement setup in Section VIII if you rerun on other hardware.

## Where the numbers come from

- Table V (decisions) and Table VI (latency): measured on 2026-11-09 with the
  shipped extension scorer and local service against `data/*benchmark*.jsonl`.
- Table VII (live traffic): the engine's published runs in `docs/BENCHMARK.md`.
- Table VIII (tests): `python -m unittest discover -s tests`,
  `tests/integration_tests/test_e2e_protection.py`, and
  `tests/integration_tests/test_security_service.js`.
