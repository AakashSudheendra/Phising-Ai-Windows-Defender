# PhishGuard AI: Windows Anti-Phishing Protection System

A comprehensive, real-time Windows desktop security and pre-navigation anti-phishing protection system that intercepts suspicious links across web, email, messaging apps (WhatsApp Web, Discord, Telegram), and documents before the remote destination can load in your browser.

---

## 1. Architecture Overview

PhishGuard AI extends the original offline heuristic detection engine into a four-tier defense architecture:

```
[ User Clicks Link ]  (Email, Discord, Telegram, WhatsApp Web, PDF, or Browser)
         │
         ▼
[ Supported Browser (Chrome, Edge, Brave, Firefox) ]
         │
         ▼ (1) webNavigation.onBeforeNavigate / blocking request
[ PhishGuard Browser Extension (Manifest V3) ]
         │
         ├─► (2) Fast In-Memory Session Cache (0ms latency for verified safe URLs)
         │
         ▼ (3) POST http://127.0.0.1:8766/api/check-url (Authenticated Local Service)
[ Local Security Service (Node.js) ]
         │
         ├─► Whitelist / Trusted Domains Check
         ├─► Protection Policy Engine (Standard vs. Strict)
         │
         ▼ (4) POST http://127.0.0.1:8765/v1/url
[ Existing Python PhishGuard AI Engine ]
         │ (19 structural heuristic signals, weights, sigmoid probability)
         ▼
[ Verdict: SAFE | SUSPICIOUS | PHISHING ]
         │
         ├─► (5) Saved in Local Security History (sensitive tokens & passwords REDACTED)
         ├─► (6) Emitted over SSE to Windows Desktop Protection Center
         │
         ▼
[ Decision Returned to Browser Extension ]
         │
         ├── SAFE: Tab is immediately allowed to navigate to destination.
         │
         └── SUSPICIOUS / PHISHING: 
               • Tab is instantly redirected to local extension interstitial:
                 `pages/interstitial.html`
               • Remote website payload NEVER loads.
               • Windows Desktop Security Alert window pops up with native notification.
               • User can click "Return to Safety" or explicitly confirm "Proceed Anyway".
```

---

## 2. Core Components

| Component | Path | Responsibility |
| --- | --- | --- |
| **Python Detection Engine** | `phishguard.py`, `model.py`, `server.py` | Core explainable phishing heuristic scoring engine (zero third-party dependencies). |
| **Local Security Service** | `services/local-security-service/` | High-speed local gateway (`127.0.0.1:8766`) managing token auth, caching, policy, privacy redaction, and database. |
| **Browser Extension** | `apps/browser-extension/` | Manifest V3 extension providing pre-navigation interception, the warning interstitial, and toolbar controls. |
| **Windows Desktop Center** | `apps/desktop/` | Modern Electron application with dark Fluent theme, dashboard metrics, Windows system tray, startup support, and alert windows. |

---

## 3. Pre-Navigation Interception Mechanism

### The Technical Challenge in Manifest V3
In modern Chromium browsers (Chrome, Edge, Brave), traditional synchronous blocking (`webRequestBlocking`) is restricted for web extensions. 

### PhishGuard's High-Assurance Solution
1. **Immediate Pre-Navigation Capture**: The extension hooks `chrome.webNavigation.onBeforeNavigate` for top-level navigations (`frameId === 0`).
2. **Instant Local Interception**: Before the browser establishes an HTTP connection to the remote server, the tab is redirected to the local extension interstitial warning page (`pages/interstitial.html`).
3. **Asynchronous Engine Analysis**: The Local Security Service checks the URL against the Python PhishGuard model in milliseconds.
4. **Automated Safe Pass-Through**: If the URL is verified `SAFE` or `TRUSTED`, the extension automatically forwards the tab to the destination URL without user intervention.
5. **Enforced Interstitial Block**: If the URL is `PHISHING` or `SUSPICIOUS`, the interstitial warning remains, explaining the exact reasons why the site was blocked.

---

## 4. Privacy & Sensitive Parameter Redaction

To prevent sensitive credentials, passwords, or session tokens from being written to logs or history, PhishGuard applies automatic query-parameter sanitization:

```javascript
// Example:
Raw URL:      https://login.bank.com/auth?token=supersecret12345&user=alice
Redacted URL: https://login.bank.com/auth?token=[REDACTED]&user=alice
```

Query parameters matching sensitive patterns (`token`, `access_token`, `auth`, `password`, `key`, `code`, `session_id`, `jwt`, `secret`) are replaced with `[REDACTED]`.

---

## 5. Quick Start & Running Locally

### Prerequisites
* **Python 3.10+** (verified with Python 3.12)
* **Node.js 18+** (verified with Node.js v24)
* **npm**

### Step 1: Start the Local Security Service
```powershell
cd "c:\Users\aakas\OneDrive\Desktop\Desktop Folders\Information secuirty project\phishguard-ai\services\local-security-service"
npm start
```
* Binds to `http://127.0.0.1:8766`.
* Automatically spawns or interfaces with the Python PhishGuard engine on port `8765`.

### Step 2: Install the Browser Extension (Chrome / Edge / Brave)
1. Open Google Chrome or Microsoft Edge.
2. Go to `chrome://extensions/` or `edge://extensions/`.
3. Enable **Developer mode** (toggle in upper right corner).
4. Click **Load unpacked**.
5. Select the folder:
   ```
   c:\Users\aakas\OneDrive\Desktop\Desktop Folders\Information secuirty project\phishguard-ai\apps\browser-extension
   ```
6. The PhishGuard AI shield icon will appear in your toolbar.

### Step 3: Launch the Windows Desktop Application
```powershell
cd "c:\Users\aakas\OneDrive\Desktop\Desktop Folders\Information secuirty project\phishguard-ai\apps\desktop"
npm start
```
* Opens the PhishGuard Windows Protection Center.
* Adds a background shield icon in the Windows taskbar system tray.
* Listens for real-time threat events and surfaces native Windows popups.

---

## 6. How to Test & Verify

### Safe Website Test
Visit:
```
https://www.google.com
```
* **Observed Behavior**: The browser extension detects the URL, checks with the local service, classifies it as `SAFE` (low risk), and loads the page immediately.

### Known Phishing Website Test
Visit or click:
```
http://paypa1-secure-login.xyz/verify
```
* **Observed Behavior**:
  1. The browser tab is immediately prevented from reaching the remote site.
  2. The PhishGuard Interstitial Warning screen appears with a **95% Phishing Risk** score.
  3. Feature breakdown lists:
     * Brand impersonation / typosquatting
     * Suspicious TLD (`.xyz`)
     * Sensitive credential keywords (`verify`, `login`)
     * Lack of HTTPS encryption
  4. A native Windows notification and dedicated alert popup appear on your desktop.
  5. The navigation event is logged in your local security history with tokens redacted.

---

## 7. Packaging for Windows (Building Installer)

To package the application into a standalone Windows `.exe` installer:

```powershell
cd "c:\Users\aakas\OneDrive\Desktop\Desktop Folders\Information secuirty project\phishguard-ai\apps\desktop"

# Install builder tooling
npm install --save-dev electron-builder

# Build Windows installer (.exe / NSIS)
npm run build:win
```
The compiled installer will be generated in `apps/desktop/dist/`.

---

## 8. Security & Origin Safeguards

* **Localhost Binding**: The local security service strictly binds to `127.0.0.1` and does not accept remote network traffic.
* **Token Authentication**: All API endpoints require an authentication token generated locally (`X-PhishGuard-Auth`).
* **Origin Checking**: External websites are strictly prohibited via CORS and origin headers from making requests or altering security settings.
* **Fail-Safe Policy**: Configurable to **Fail-Open** (with desktop warning) or **Fail-Closed** (block unverified URLs) if the local detection service is unreachable.
