// Secure bridge between Electron main process and the renderer (UI)
// Exposes only the exact functions the UI needs, preventing raw Node.js access.

const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('vault', {
  // Authentication methods
  isFirstRun: () => ipcRenderer.invoke('vault:isFirstRun'),
  setup: (password) => ipcRenderer.invoke('vault:setup', password),
  unlock: (password) => ipcRenderer.invoke('vault:unlock', password),
  recover: (data) => ipcRenderer.invoke('vault:recover', data),
  lock: () => ipcRenderer.invoke('vault:lock'),

  // Vault CRUD operations (Main process attaches Session Token internally)
  getItems: () => ipcRenderer.invoke('vault:getItems'),
  getAudit: () => ipcRenderer.invoke('vault:getAudit'),
  addItem: (item) => ipcRenderer.invoke('vault:addItem', item),
  deleteItem: (id) => ipcRenderer.invoke('vault:deleteItem', id),

  // Permission response from the UI
  respondToPermission: (requestId, approved) =>
    ipcRenderer.invoke('vault:respondToPermission', requestId, approved),

  // Agent Management
  listAgents: () => ipcRenderer.invoke('vault:listAgents'),
  registerAgent: (agent) => ipcRenderer.invoke('vault:registerAgent', agent),
  revokeAgent: (cardId) => ipcRenderer.invoke('vault:revokeAgent', cardId),

  // Listen for incoming agent permission requests pushed from the main process
  onPermissionRequest: (callback) => {
    // Remove existing listener if any, then register new callback
    ipcRenderer.removeAllListeners('permission:incoming');
    ipcRenderer.on('permission:incoming', (_, data) => callback(data));
  }
});
