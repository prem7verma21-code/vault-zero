// Electron main process: manages app lifecycle, spawns backend, and acts as API proxy.
// Disables Node.js access in renderer for security, storing Session Token in memory here.

const { app, BrowserWindow, ipcMain } = require('electron');
const { spawn } = require('child_process');
const path = require('path');
const http = require('http');
const process = require('process');
const fs = require('fs');

// Set app.name to align Electron's userData path with Python backend's AppData directory
app.name = 'Vault-Zero';

let mainWindow = null;
let backendProcess = null;
let sessionToken = null;
let pollInterval = null;
const activeRequestIds = new Set();

// ---------------------------------------------------------------------------
// HTTP API PROXY HELPER
// ---------------------------------------------------------------------------
// Electron main process communicates with the FastAPI backend on localhost.
// The session token is stored exclusively here in main memory for security.
function makeRequest(method, apiPath, data = null, token = null) {
  return new Promise((resolve, reject) => {
    const postData = data ? JSON.stringify(data) : '';
    const headers = {
      'Content-Type': 'application/json',
      'Content-Length': Buffer.byteLength(postData)
    };

    if (token) {
      headers['Authorization'] = `Bearer ${token}`;
    }

    const options = {
      hostname: '127.0.0.1',
      port: 8765,
      path: apiPath,
      method: method,
      headers: headers
    };

    const req = http.request(options, (res) => {
      let body = '';
      res.on('data', (chunk) => { body += chunk; });
      res.on('end', () => {
        let parsed = {};
        try {
          if (body) {
            parsed = JSON.parse(body);
          }
        } catch (e) {
          return reject(new Error(`Failed to parse response body: ${body}`));
        }

        if (res.statusCode >= 200 && res.statusCode < 300) {
          resolve(parsed);
        } else {
          reject(new Error(parsed.detail || `HTTP Error ${res.statusCode}`));
        }
      });
    });

    req.on('error', (err) => {
      reject(err);
    });

    if (data) {
      req.write(postData);
    }
    req.end();
  });
}

// ---------------------------------------------------------------------------
// BACKGROUND PERMISSION POLLING
// ---------------------------------------------------------------------------
// Polls FastAPI GET /pending_permissions in the background when vault is unlocked.
// Pushes incoming requests to the UI renderer process via secure IPC.
function startPermissionPolling(win) {
  if (pollInterval) clearInterval(pollInterval);

  pollInterval = setInterval(async () => {
    if (!sessionToken) {
      stopPermissionPolling();
      return;
    }
    try {
      const response = await makeRequest('GET', '/api/v1/agent/pending_permissions', null, sessionToken);
      if (response && response.pending && response.pending.length > 0) {
        for (const req of response.pending) {
          if (!activeRequestIds.has(req.request_id)) {
            activeRequestIds.add(req.request_id);
            if (win && !win.isDestroyed()) {
              win.webContents.send('permission:incoming', req);
            }
          }
        }

        // Remove active IDs that are no longer pending (resolved on agent side)
        const currentIds = new Set(response.pending.map(r => r.request_id));
        for (const id of activeRequestIds) {
          if (!currentIds.has(id)) {
            activeRequestIds.delete(id);
          }
        }
      } else {
        activeRequestIds.clear();
      }
    } catch (err) {
      console.error('[Electron Main] Error polling pending permissions:', err.message);
    }
  }, 2000);
}

function stopPermissionPolling() {
  if (pollInterval) {
    clearInterval(pollInterval);
    pollInterval = null;
  }
  activeRequestIds.clear();
}

// ---------------------------------------------------------------------------
// SECURE IPC ENDPOINT HANDLERS
// ---------------------------------------------------------------------------
ipcMain.handle('vault:isFirstRun', async () => {
  const dbPath = path.join(app.getPath('userData'), 'vault.db');
  return !fs.existsSync(dbPath);
});

ipcMain.handle('vault:setup', async (event, password) => {
  try {
    const result = await makeRequest('POST', '/api/v1/auth/setup', { password });
    if (result && result.session_token) {
      sessionToken = result.session_token;
      startPermissionPolling(mainWindow);
      return { success: true, recovery_code: result.recovery_code };
    }
    return { success: false, error: 'Setup failed: no token/code returned' };
  } catch (err) {
    return { success: false, error: err.message };
  }
});

ipcMain.handle('vault:recover', async (event, { recovery_code, new_password }) => {
  try {
    const result = await makeRequest('POST', '/api/v1/auth/recover', { recovery_code, new_password });
    if (result && result.session_token) {
      sessionToken = result.session_token;
      startPermissionPolling(mainWindow);
      return { success: true, new_recovery_code: result.new_recovery_code };
    }
    return { success: false, error: 'Recovery failed: no token/code returned' };
  } catch (err) {
    return { success: false, error: err.message };
  }
});

ipcMain.handle('vault:unlock', async (event, password) => {
  try {
    const result = await makeRequest('POST', '/api/v1/auth/unlock', { password });
    if (result && result.session_token) {
      sessionToken = result.session_token;
      startPermissionPolling(mainWindow);
      return { success: true };
    }
    return { success: false, error: 'Unlock failed: no token returned' };
  } catch (err) {
    return { success: false, error: err.message };
  }
});

ipcMain.handle('vault:lock', async () => {
  try {
    if (sessionToken) {
      await makeRequest('POST', '/api/v1/auth/lock', null, sessionToken);
    }
  } catch (err) {
    console.error('[Electron Main] Lock request failed:', err.message);
  } finally {
    sessionToken = null;
    stopPermissionPolling();
  }
  return { success: true };
});

ipcMain.handle('vault:getItems', async () => {
  if (!sessionToken) throw new Error('Vault is locked');
  return await makeRequest('GET', '/api/v1/vault/items', null, sessionToken);
});

ipcMain.handle('vault:getAudit', async () => {
  if (!sessionToken) throw new Error('Vault is locked');
  return await makeRequest('GET', '/api/v1/vault/audit', null, sessionToken);
});

ipcMain.handle('vault:addItem', async (event, item) => {
  if (!sessionToken) throw new Error('Vault is locked');
  return await makeRequest('POST', '/api/v1/vault/items', item, sessionToken);
});

ipcMain.handle('vault:deleteItem', async (event, id) => {
  if (!sessionToken) throw new Error('Vault is locked');
  return await makeRequest('DELETE', `/api/v1/vault/items/${id}`, null, sessionToken);
});

ipcMain.handle('vault:respondToPermission', async (event, requestId, approved) => {
  if (!sessionToken) throw new Error('Vault is locked');
  try {
    const result = await makeRequest('POST', '/api/v1/agent/respond_permission', {
      request_id: requestId,
      approved: approved
    }, sessionToken);
    activeRequestIds.delete(requestId);
    return result;
  } catch (err) {
    console.error('[Electron Main] Error responding to permission:', err.message);
    throw err;
  }
});

// Agent Management IPC handlers
ipcMain.handle('vault:listAgents', async () => {
  if (!sessionToken) throw new Error('Vault is locked');
  return await makeRequest('GET', '/api/v1/agent/list', null, sessionToken);
});

ipcMain.handle('vault:registerAgent', async (event, agentData) => {
  if (!sessionToken) throw new Error('Vault is locked');
  return await makeRequest('POST', '/api/v1/agent/register', {
    agent_id: agentData.agent_id,
    permissions: agentData.permissions,
    ttl_hours: agentData.ttl_hours
  }, sessionToken);
});

ipcMain.handle('vault:revokeAgent', async (event, cardId) => {
  if (!sessionToken) throw new Error('Vault is locked');
  return await makeRequest('DELETE', `/api/v1/agent/revoke/${cardId}`, null, sessionToken);
});

// ---------------------------------------------------------------------------
// BACKEND SERVICE MANAGEMENT
// ---------------------------------------------------------------------------
function startBackend() {
  const pythonCmd = process.platform === 'win32' ? 'python' : 'python3';
  const backendPath = path.join(__dirname, '..', 'backend');

  console.log(`[Electron Main] Spawning backend with command: ${pythonCmd} run_server.py`);
  
  backendProcess = spawn(pythonCmd, ['run_server.py'], {
    cwd: backendPath,
    detached: false,
    stdio: 'pipe',
    env: {
      ...process.env,
      PARENT_PID: process.pid.toString()
    }
  });

  backendProcess.stdout.on('data', (data) => {
    console.log(`[Python Backend]: ${data.toString().trim()}`);
  });

  backendProcess.stderr.on('data', (data) => {
    console.error(`[Python Backend Error]: ${data.toString().trim()}`);
  });

  backendProcess.on('close', (code) => {
    console.log(`[Electron Main] Backend process closed with code ${code}`);
  });
}

function stopBackend() {
  if (backendProcess) {
    console.log('[Electron Main] Stopping Python backend...');
    backendProcess.kill();
    backendProcess = null;
  }
  stopPermissionPolling();
  sessionToken = null;
}

// ---------------------------------------------------------------------------
// MAIN APPLICATION WINDOW LIFECYCLE
// ---------------------------------------------------------------------------
function createWindow() {
  mainWindow = new BrowserWindow({
    width: 380,
    height: 680,
    resizable: false,
    frame: true,
    title: "Vault-Zero",
    icon: path.join(__dirname, 'assets', 'Vault-Zero-logo.jpeg'),
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      sandbox: true,
      enableRemoteModule: false,
      preload: path.join(__dirname, 'preload.js')
    }
  });

  if (process.platform === 'darwin') {
    app.dock.setIcon(path.join(__dirname, 'assets', 'Vault-Zero-logo.jpeg'));
  }

  mainWindow.setMenuBarVisibility(false);
  mainWindow.loadFile(path.join(__dirname, 'src', 'index.html'));

  // Strict Security: Prevent DevTools from remaining open in production
  if (app.isPackaged) {
    mainWindow.webContents.on('devtools-opened', () => {
      mainWindow.webContents.closeDevTools();
    });
  }

  mainWindow.on('closed', () => {
    mainWindow = null;
  });
}

// Startup lifecycle
app.whenReady().then(() => {
  // 1. Spawn backend
  startBackend();

  // 2. Wait 2 seconds for servers to bind, then show the desktop shell
  setTimeout(() => {
    createWindow();
  }, 2000);
});

// App termination triggers cleanup
app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    app.quit();
  }
});

app.on('will-quit', () => {
  stopBackend();
});

process.on('exit', () => {
  stopBackend();
});
