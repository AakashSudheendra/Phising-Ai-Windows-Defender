# PhishGuard AI Browser Extension

This is an unpacked Chromium extension for local testing in Chrome, Edge,
Brave, and other Chromium-based browsers.

The extension checks the current tab URL or a pasted URL using the same
offline JavaScript scoring model as the browser demo. It does not send URLs to
PhishGuard, a lookup server, or a third-party API.

## Install Locally

1. Open `chrome://extensions` or `edge://extensions`.
2. Enable developer mode.
3. Choose **Load unpacked**.
4. Select `browser-extension/chromium`.
5. Pin **PhishGuard AI** to the browser toolbar.

## Use It

1. Open a normal `http://` or `https://` page.
2. Click the PhishGuard AI extension icon.
3. Click **Check current page**.
4. Review the verdict, risk score, guidance, and triggered features.

You can also paste a URL into the popup without visiting it first.

## Privacy Model

- Active-tab URL only, after the user opens the popup.
- No browsing-history permission.
- No background page scanning.
- No external network request.
- No API key or cloud service.

## Current Limits

- URL scoring only. Email scoring remains in the web demo and CLI.
- No automatic page blocking yet.
- No redirect-chain resolution unless using `phishguard serve`; static browser
  extension code cannot safely follow links server-side.
- This is not yet packaged for the Chrome Web Store or Microsoft Edge Add-ons.
