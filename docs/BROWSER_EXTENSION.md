# Browser Extension

PhishGuard AI includes an unpacked Chromium extension prototype in
`browser-extension/chromium`.

This gives non-CLI users a practical workflow: open a page, click the
extension, scan the current tab URL, and review a plain-language verdict with
the triggered features. Scoring runs locally in the popup with the same
JavaScript model used by the browser demo.

## Local Install

1. Open `chrome://extensions` or `edge://extensions`.
2. Turn on developer mode.
3. Select **Load unpacked**.
4. Choose the `browser-extension/chromium` folder.
5. Pin the extension to the browser toolbar.

## User Experience

- **Current-page scan:** one click checks the active tab URL.
- **Paste-and-check:** users can test a URL before visiting it.
- **Explainable result:** verdict, percentage score, guidance, and feature
  values appear in the popup.
- **Private by design:** no server lookup, no API key, no browsing-history
  permission, and no background scanning.

## Why This Exists

The CLI, GitHub Action, SARIF output, and REST API are useful for engineers and
security teams. The browser extension is the first user-facing packaging step:
it makes PhishGuard feel like a tool someone can reach for during normal web
use, not only during terminal or CI work.

## Limits

This prototype does not block navigation, inspect full-page content, or follow
redirect chains. It should be treated as an explainable warning signal, not a
browser security replacement.
