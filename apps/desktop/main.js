/**
 * PhishGuard AI Windows Desktop Application — Main Process.
 * Manages Electron lifecycle, local security service, native Windows notifications,
 * system tray, auto-start, and security alert popup windows.
 */

const { app, BrowserWindow, ipcMain, Notification, Tray, Menu } = require('electron');
const path = require('path');
const http = require('http');

const { startServer, stopServer } = require('../../services/local-security-service/index');
const { getOrCreateAuthToken } = require('../../services/local-security-service/auth');
const { db } = require('../../services/local-security-service/database');
const { policy } = require('../../services/local-security-service/policy');
const { checkEngineHealth } = require('../../services/local-security-service/engine-client');

let mainWindow = null;
let alertWindow = null;
let tray = null;
let serviceStarted = false;
let isQuitting = false;

const SERVICE_PORT = 8766;
const ICON_PATH = path.join(__dirname, 'assets', 'icon32.png');

/**
 * Initializes and starts the Local Security Service.
 */
async function initializeService() {
  try {
    await startServer(SERVICE_PORT);
    serviceStarted = true;
    console.log('[DesktopMain] Local Security Service launched successfully.');
  } catch (err) {
    if (err.code === 'EADDRINUSE') {
      console.log('[DesktopMain] Local Security Service is already running on port 8766.');
      serviceStarted = true;
    } else {
      console.error('[DesktopMain] Error starting Local Security Service:', err.message);
    }
  }

  // Hook into policy engine alerts for real-time notifications
  policy.onAlert((alertEvent) => {
    handleThreatAlert(alertEvent);
  });
}

/**
 * Handles incoming threat alert events (Windows Notification + Popup).
 */
function handleThreatAlert(event) {
  const settings = db.getSettings();

  // 1. Send IPC to main dashboard
  if (mainWindow && !mainWindow.isDestroyed()) {
    mainWindow.webContents.send('threat-alert', event);
  }

  // 2. Show Native Windows Desktop Notification
  if (settings.desktopNotifications && Notification.isSupported()) {
    const isPhishing = event.classification === 'PHISHING';
    const notif = new Notification({
      title: isPhishing ? '🛡️ PhishGuard: Phishing Website Blocked' : '⚠️ PhishGuard: Suspicious Website Warning',
      body: `Blocked attempted navigation to:\n${event.url}\nThreat Score: ${event.riskScore || 95}%`,
      icon: ICON_PATH,
      urgency: 'critical',
    });

    notif.on('click', () => {
      showThreatAlertWindow(event);
    });

    notif.show();
  }

  // 3. Open dedicated Security Warning Window
  if (settings.warningPopup) {
    showThreatAlertWindow(event);
  }
}

/**
 * Creates or focuses the dedicated Windows Security Warning Popup Window.
 */
function showThreatAlertWindow(threatData) {
  if (alertWindow && !alertWindow.isDestroyed()) {
    alertWindow.close();
  }

  alertWindow = new BrowserWindow({
    width: 620,
    height: 600,
    resizable: false,
    minimizable: false,
    maximizable: false,
    alwaysOnTop: true,
    title: 'PhishGuard Security — Warning',
    icon: ICON_PATH,
    backgroundColor: '#ffffff',
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      nodeIntegration: false,
      contextIsolation: true,
    },
  });

  alertWindow.setMenu(null);
  alertWindow.setAlwaysOnTop(true, 'screen-saver');
  alertWindow.setVisibleOnAllWorkspaces(true);
  alertWindow.loadFile(path.join(__dirname, 'renderer', 'alert.html'), {
    query: { data: encodeURIComponent(JSON.stringify(threatData)) },
  });

  alertWindow.once('ready-to-show', () => {
    alertWindow.show();
    alertWindow.focus();
  });

  alertWindow.on('closed', () => {
    alertWindow = null;
  });
}

/**
 * Creates the primary application dashboard window.
 */
function createMainWindow() {
  mainWindow = new BrowserWindow({
    width: 1080,
    height: 720,
    minWidth: 880,
    minHeight: 600,
    title: 'PhishGuard — Enterprise Endpoint Security',
    icon: ICON_PATH,
    backgroundColor: '#f8fafc',
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      nodeIntegration: false,
      contextIsolation: true,
    },
  });

  mainWindow.setMenu(null);
  mainWindow.loadFile(path.join(__dirname, 'renderer', 'index.html'));

  mainWindow.on('close', (e) => {
    if (!isQuitting) {
      e.preventDefault();
      mainWindow.hide(); // Minimize to system tray
      if (tray && Notification.isSupported()) {
        new Notification({
          title: 'PhishGuard AI Running in Background',
          body: 'Real-time anti-phishing protection is active in your system tray.',
          icon: ICON_PATH,
        }).show();
      }
    }
  });
}

/**
 * Creates the Windows System Tray Icon and Context Menu.
 */
function createTray() {
  try {
    tray = new Tray(ICON_PATH);
    const contextMenu = Menu.buildFromTemplate([
      {
        label: 'Open PhishGuard Dashboard',
        click: () => {
          if (mainWindow) {
            mainWindow.show();
            mainWindow.focus();
          }
        },
      },
      { type: 'separator' },
      {
        label: 'Protection: Active',
        type: 'checkbox',
        checked: db.getSettings().realTimeProtection,
        click: (menuItem) => {
          db.updateSettings({ realTimeProtection: menuItem.checked });
          if (mainWindow && !mainWindow.isDestroyed()) {
            mainWindow.webContents.send('protection-toggled', menuItem.checked);
          }
        },
      },
      { type: 'separator' },
      {
        label: 'Exit PhishGuard AI',
        click: () => {
          isQuitting = true;
          app.quit();
        },
      },
    ]);

    tray.setToolTip('PhishGuard AI — Real-Time Anti-Phishing Protection');
    tray.setContextMenu(contextMenu);

    tray.on('double-click', () => {
      if (mainWindow) {
        mainWindow.show();
        mainWindow.focus();
      }
    });
  } catch (err) {
    console.warn('[DesktopMain] Could not initialize system tray:', err.message);
  }
}

/**
 * Configure auto-start on Windows startup.
 */
function configureAutoStart(enable) {
  try {
    app.setLoginItemSettings({
      openAtLogin: enable,
      path: process.execPath,
      args: ['--hidden'],
    });
  } catch (err) {
    console.warn('[DesktopMain] Failed to configure login item settings:', err.message);
  }
}

// ──────────────────────────────────────────────
// IPC Handlers
// ──────────────────────────────────────────────

ipcMain.handle('get-stats', async () => {
  const stats = db.getStats();
  const engineOnline = await checkEngineHealth();
  return { ...stats, engineOnline };
});

ipcMain.handle('get-history', (event, params) => {
  return db.getEvents(params || {});
});

ipcMain.handle('clear-history', () => {
  return db.clearEvents();
});

ipcMain.handle('get-settings', () => {
  return db.getSettings();
});

ipcMain.handle('update-settings', (event, updates) => {
  const updated = db.updateSettings(updates);
  if (typeof updates.autoStart === 'boolean') {
    configureAutoStart(updates.autoStart);
  }
  return updated;
});

ipcMain.handle('get-trusted-domains', () => {
  return db.getTrustedDomains();
});

ipcMain.handle('add-trusted-domain', (event, domain) => {
  return db.addTrustedDomain(domain);
});

ipcMain.handle('remove-trusted-domain', (event, domain) => {
  return db.removeTrustedDomain(domain);
});

ipcMain.handle('get-service-status', async () => {
  const engineOnline = await checkEngineHealth();
  const settings = db.getSettings();
  return {
    serviceOnline: true,
    engineOnline,
    realTimeProtection: settings.realTimeProtection,
    token: getOrCreateAuthToken(),
  };
});

ipcMain.handle('simulate-threat', async (event, testUrl) => {
  const urlToTest = testUrl || 'http://paypa1-secure-login.xyz/verify';
  const decision = await policy.evaluateUrl(urlToTest, { browser: 'Manual Security Simulation' });
  return decision;
});

ipcMain.handle('cancel-navigation', async (event, params) => {
  policy.broadcastCancelNavigation(params || {});
  if (alertWindow && !alertWindow.isDestroyed()) {
    alertWindow.close();
  }
  return { ok: true };
});

function extractUrlFromArgs(args) {
  if (!args || !Array.isArray(args)) return null;
  for (const arg of args) {
    if (typeof arg === 'string') {
      const clean = arg.trim().replace(/^["']|["']$/g, '');
      if (clean.startsWith('http://') || clean.startsWith('https://')) {
        return clean;
      }
      if (clean.startsWith('phishguard://')) {
        return clean.replace(/^phishguard:\/\//, '');
      }
    }
  }
  return null;
}

async function handleIncomingExternalUrl(rawUrl) {
  console.log('[DesktopMain] Intercepted external URL click:', rawUrl);
  try {
    const decision = await policy.evaluateUrl(rawUrl, {
      browser: 'WhatsApp / External Application Click',
      isNavigation: true,
    });

    if (decision.action === 'block' || decision.action === 'warn') {
      // Threat detected: Do NOT open browser, pop up the security alert window!
      showThreatAlertWindow(decision);
    } else {
      // Safe destination: open in default browser
      const { shell } = require('electron');
      shell.openExternal(rawUrl);
    }
  } catch (err) {
    console.error('[DesktopMain] Error handling external link:', err);
  }
}

// Single Instance Lock (handles multiple clicks from WhatsApp/other apps)
const gotTheLock = app.requestSingleInstanceLock();

if (!gotTheLock) {
  app.quit();
} else {
  app.on('second-instance', (event, commandLine) => {
    const incomingUrl = extractUrlFromArgs(commandLine);
    if (incomingUrl) {
      handleIncomingExternalUrl(incomingUrl);
    } else if (mainWindow) {
      if (mainWindow.isMinimized()) mainWindow.restore();
      mainWindow.show();
      mainWindow.focus();
    }
  });

  // App Lifecycle
  app.whenReady().then(async () => {
    await initializeService();
    createMainWindow();
    createTray();

    // Check if initial launch had a URL argument
    const initialUrl = extractUrlFromArgs(process.argv);
    if (initialUrl) {
      handleIncomingExternalUrl(initialUrl);
    }

    app.on('activate', () => {
      if (BrowserWindow.getAllWindows().length === 0) {
        createMainWindow();
      } else if (mainWindow) {
        mainWindow.show();
      }
    });
  });
}

app.on('before-quit', async () => {
  isQuitting = true;
  await stopServer();
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin' && isQuitting) {
    app.quit();
  }
});
