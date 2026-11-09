/**
 * Electron Preload Script.
 * Secure context bridge exposing safe IPC channels and security service controls to the renderer.
 */

const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('phishguardAPI', {
  // Service info & stats
  getStats: () => ipcRenderer.invoke('get-stats'),
  getHistory: (params) => ipcRenderer.invoke('get-history', params),
  clearHistory: () => ipcRenderer.invoke('clear-history'),

  // Settings
  getSettings: () => ipcRenderer.invoke('get-settings'),
  updateSettings: (settings) => ipcRenderer.invoke('update-settings', settings),

  // Trusted domains
  getTrustedDomains: () => ipcRenderer.invoke('get-trusted-domains'),
  addTrustedDomain: (domain) => ipcRenderer.invoke('add-trusted-domain', domain),
  removeTrustedDomain: (domain) => ipcRenderer.invoke('remove-trusted-domain', domain),

  // Threat alert events
  onThreatAlert: (callback) => {
    const subscription = (event, data) => callback(data);
    ipcRenderer.on('threat-alert', subscription);
    return () => ipcRenderer.removeListener('threat-alert', subscription);
  },

  // Test threat simulation
  simulateThreat: (url) => ipcRenderer.invoke('simulate-threat', url),

  // Service status
  getServiceStatus: () => ipcRenderer.invoke('get-service-status'),

  // Cancel navigation & close tab
  cancelNavigation: (params) => ipcRenderer.invoke('cancel-navigation', params),

  // Platform info
  platform: process.platform,
});
