/**
 * Vault-Zero Renderer — Step 1.8C
 *
 * Vanilla JavaScript only. No frameworks, no external libraries.
 * All communication with the backend goes through window.vault.*
 * (defined in preload.js via Electron contextBridge).
 *
 * This file:
 *   - Manages screen navigation (showScreen)
 *   - Handles the Unlock flow (Screen 1)
 *   - Loads and renders vault items (Screen 2 — Dashboard)
 *   - Handles the Add Item form (Screen 3)
 *   - Listens for and displays incoming agent permission dialogs (Screen 4)
 *   - Loads and renders the Audit Log (Screen 5)
 *
 * Security note: This file has zero access to Node.js APIs, the file system,
 * or the network. All of that lives exclusively in the Electron main process.
 */

'use strict';

// ---------------------------------------------------------------------------
// STATE
// ---------------------------------------------------------------------------

// Tracks the active permission request ID so the Approve/Deny buttons
// can reference the right request when the user clicks.
let activePermissionRequestId = null;

// Stores the countdown timer interval so it can be cleared when a
// permission dialog is resolved (approved, denied, or timed out).
let permCountdownInterval = null;

// Cleanup function for the currently-revealed vault item, or null when nothing
// is shown. Set whenever a Reveal button is clicked. Calling it restores the
// row to its hidden state and clears its countdown timer. Single-reveal-at-a-
// time policy: clicking another Reveal first calls this, then opens the new one.
let activeRevealCleanup = null;

// Tracks whether the vault is currently unlocked. Drives the window-level idle
// auto-lock timer below — we only start the timer while unlocked, and we stop
// it as soon as the vault locks (manually, via idle expiry, or on app close).
let isUnlocked = false;

// Idle auto-lock: if the user has not interacted with the window for this many
// milliseconds while the vault is unlocked, we lock automatically. This is
// distinct from the per-item reveal timer (which is server-driven via
// `expires_at` and lives inside handleRevealItem).
const IDLE_LOCK_MS = 30 * 1000;
let idleLockTimeoutId = null;

function resetIdleTimer() {
  if (!isUnlocked) return;
  if (idleLockTimeoutId !== null) {
    clearTimeout(idleLockTimeoutId);
  }
  idleLockTimeoutId = setTimeout(() => {
    console.log('idle lock triggered');
    performLock();
  }, IDLE_LOCK_MS);
}

function startIdleTimer() {
  isUnlocked = true;
  resetIdleTimer();
}

function stopIdleTimer() {
  isUnlocked = false;
  if (idleLockTimeoutId !== null) {
    clearTimeout(idleLockTimeoutId);
    idleLockTimeoutId = null;
  }
}

// Any of these events count as "user is here" — reset the countdown.
// Passive listeners so we never block scroll/input. Attached once at module
// load; resetIdleTimer is a no-op while the vault is locked, so leaving them
// permanently registered is cheap and avoids add/remove churn on every lock.
['mousemove', 'keydown', 'click'].forEach(evt => {
  document.addEventListener(evt, resetIdleTimer, { passive: true });
});


// ---------------------------------------------------------------------------
// SCREEN NAVIGATION
// ---------------------------------------------------------------------------

/**
 * Shows one screen and hides all others.
 * Uses the 'active' CSS class (defined in style.css) to control visibility.
 *
 * @param {string} screenId - The ID suffix, e.g. 'unlock', 'dashboard', 'add-item', 'audit'
 */
function showScreen(screenId) {
  document.querySelectorAll('.screen').forEach(s => s.classList.remove('active'));
  const target = document.getElementById('screen-' + screenId);
  if (target) {
    target.classList.add('active');
  }
}


// ---------------------------------------------------------------------------
// SCREEN 1: UNLOCK
// ---------------------------------------------------------------------------

const unlockPasswordInput = document.getElementById('unlock-password');
const unlockBtn = document.getElementById('unlock-btn');
const unlockError = document.getElementById('unlock-error');

/**
 * Clears the unlock error message area.
 */
function clearUnlockError() {
  unlockError.textContent = '';
}

/**
 * Sends the password to the main process, which forwards it to the FastAPI
 * /auth/unlock endpoint. On success the session_token is stored in the
 * main process (never here). We just navigate to the dashboard.
 */
async function handleUnlock() {
  clearUnlockError();

  const password = unlockPasswordInput.value;
  if (!password) {
    unlockError.textContent = 'Enter your master password.';
    return;
  }

  unlockBtn.disabled = true;
  unlockBtn.textContent = 'Unlocking…';

  try {
    const result = await window.vault.unlock(password);
    if (result && result.success) {
      unlockPasswordInput.value = '';
      showScreen('dashboard');
      loadDashboard();
      startIdleTimer();
    } else {
      // result.error comes from the main process catching a FastAPI 401
      unlockError.textContent = result.error || 'Wrong password.';
      unlockPasswordInput.select();
    }
  } catch (err) {
    unlockError.textContent = 'Could not reach vault server.';
    console.error('[Renderer] Unlock error:', err);
  } finally {
    unlockBtn.disabled = false;
    unlockBtn.textContent = 'Unlock';
  }
}

// Trigger on button click and Enter key inside the password field
unlockBtn.addEventListener('click', handleUnlock);
unlockPasswordInput.addEventListener('keydown', (e) => {
  if (e.key === 'Enter') handleUnlock();
});


// ---------------------------------------------------------------------------
// SCREEN 2: DASHBOARD
// ---------------------------------------------------------------------------

const itemsContainer = document.getElementById('items-container');
const emptyState = document.getElementById('empty-state');
const btnAddItem = document.getElementById('btn-add-item');
const btnLock = document.getElementById('btn-lock');
const btnOpenAudit = document.getElementById('btn-open-audit');

/**
 * Maps category slugs to their display badge text.
 * Keeps the badge short and readable at 9px.
 */
const CATEGORY_LABELS = {
  'API KEY': 'API KEY',
  'URL':     'URL',
  'ID':      'ID',
  api_key:  'API Key',
  password: 'Password',
  token:    'Token',
  memory:   'Memory',
};

/**
 * Loads vault items from the backend and renders them in the dashboard.
 * Items are grouped: each row shows category badge → label → delete button.
 * Never shows decrypted values — only labels are returned by the API.
 */
async function loadDashboard() {
  itemsContainer.innerHTML = '';

  try {
    const data = await window.vault.getItems();
    const items = data && data.items ? data.items : [];

    if (items.length === 0) {
      itemsContainer.appendChild(emptyState);
      return;
    }

    // Sort by created_at descending so newest items appear first
    items.sort((a, b) => b.created_at - a.created_at);

    items.forEach(item => {
      const row = document.createElement('div');
      row.className = 'vault-item';
      row.setAttribute('data-id', item.id);

      const badge = document.createElement('span');
      const categoryClass = (item.category || '').toLowerCase().replace(/ /g, '_');
      badge.className = `category-badge badge-${categoryClass}`;
      badge.textContent = CATEGORY_LABELS[item.category] || item.category;

      const label = document.createElement('span');
      label.className = 'vault-item-label';
      label.textContent = item.label;
      label.title = item.label; // tooltip for long labels

      const revealBtn = document.createElement('button');
      revealBtn.className = 'item-reveal-btn';
      revealBtn.textContent = 'Reveal';
      revealBtn.title = `Reveal "${item.label}" (auto-hides after 30s)`;
      revealBtn.setAttribute('aria-label', `Reveal ${item.label}`);
      revealBtn.dataset.state = 'reveal';
      revealBtn.addEventListener('click', () => handleRevealItem(row, label, revealBtn, item));

      const deleteBtn = document.createElement('button');
      deleteBtn.className = 'item-delete-btn';
      deleteBtn.textContent = '✕';
      deleteBtn.title = `Delete "${item.label}"`;
      deleteBtn.setAttribute('aria-label', `Delete ${item.label}`);
      deleteBtn.addEventListener('click', () => handleDeleteItem(item.id, item.label));

      row.appendChild(badge);
      row.appendChild(label);
      row.appendChild(revealBtn);
      row.appendChild(deleteBtn);
      itemsContainer.appendChild(row);
    });

  } catch (err) {
    itemsContainer.innerHTML = '';
    const errMsg = document.createElement('div');
    errMsg.className = 'empty-state';
    errMsg.textContent = 'Failed to load items.';
    itemsContainer.appendChild(errMsg);
    console.error('[Renderer] loadDashboard error:', err);
  }
}

/**
 * Asks the user to confirm before permanently deleting a vault item.
 * On confirmation, calls the delete API and reloads the dashboard.
 *
 * @param {string} id    - The UUID of the vault item
 * @param {string} label - The human-readable label (for the confirmation dialog)
 */
async function handleDeleteItem(id, label) {
  if (!confirm(`Delete "${label}"?\n\nThis cannot be undone.`)) return;

  try {
    await window.vault.deleteItem(id);
    loadDashboard();
  } catch (err) {
    alert(`Failed to delete "${label}". Check that the vault is still unlocked.`);
    console.error('[Renderer] deleteItem error:', err);
  }
}

/**
 * Reveals an item's plaintext value inline for 30 seconds, then auto-hides.
 *
 * Single-reveal-at-a-time: if another row is currently revealed, hide it first.
 * The label span is replaced by a monospace value box and a countdown timer
 * derived from the server-supplied `expires_at`. While revealed, the button
 * becomes "Copy" — clicking it copies the value to the clipboard and briefly
 * shows "Copied!" without affecting the auto-hide countdown. The row only
 * restores to its label-only state when the timer expires, another row is
 * revealed, or the vault is locked.
 *
 * @param {HTMLElement} row        - The .vault-item row element
 * @param {HTMLElement} labelEl    - The label span being temporarily replaced
 * @param {HTMLElement} revealBtn  - The Reveal button (becomes "Copy" while shown)
 * @param {{id: string, label: string}} item
 */
async function handleRevealItem(row, labelEl, revealBtn, item) {
  // If THIS row is currently revealed, the button acts as Copy — copy the
  // visible value to the clipboard and flash "Copied!" for 1.5s. The reveal
  // state and 30s auto-hide countdown are intentionally untouched.
  if (revealBtn.dataset.state === 'copy') {
    const valueBox = row.querySelector('.reveal-value-box');
    const value = valueBox ? valueBox.textContent : '';
    if (!value) return;
    try {
      await navigator.clipboard.writeText(value);
    } catch (err) {
      console.error('[Renderer] Copy revealed value failed:', err);
      return;
    }
    revealBtn.textContent = 'Copied!';
    setTimeout(() => {
      // Only revert if we're still in copy state — cleanup may have run.
      if (revealBtn.dataset.state === 'copy') {
        revealBtn.textContent = 'Copy';
      }
    }, 1500);
    return;
  }

  // If a different row is currently revealed, close it first.
  if (typeof activeRevealCleanup === 'function') {
    activeRevealCleanup();
  }

  revealBtn.disabled = true;
  revealBtn.textContent = '...';

  let response;
  try {
    response = await window.vault.revealItem(item.id);
  } catch (err) {
    revealBtn.disabled = false;
    revealBtn.textContent = 'Reveal';
    alert(`Failed to reveal "${item.label}".`);
    console.error('[Renderer] revealItem error:', err);
    return;
  }

  const value = response && response.value;
  const expiresAt = response && response.expires_at;
  if (!value || !expiresAt) {
    revealBtn.disabled = false;
    revealBtn.textContent = 'Reveal';
    return;
  }

  // Swap the label area for value box + countdown.
  const valueBox = document.createElement('code');
  valueBox.className = 'reveal-value-box';
  valueBox.textContent = value;
  valueBox.title = value;

  const timer = document.createElement('span');
  timer.className = 'reveal-timer';

  // Insert the box where the label was. We don't remove labelEl from the DOM —
  // we just toggle visibility so we can restore it cleanly on cleanup.
  labelEl.style.display = 'none';
  row.insertBefore(valueBox, revealBtn);
  row.insertBefore(timer, revealBtn);

  revealBtn.disabled = false;
  revealBtn.textContent = 'Copy';
  revealBtn.dataset.state = 'copy';

  let intervalId = null;
  let cleanedUp = false;

  function tick() {
    const remaining = Math.max(0, expiresAt - Math.floor(Date.now() / 1000));
    timer.textContent = `${remaining}s`;
    if (remaining <= 0) {
      cleanup();
    }
  }

  function cleanup() {
    if (cleanedUp) return;
    cleanedUp = true;
    if (intervalId !== null) {
      clearInterval(intervalId);
      intervalId = null;
    }
    if (valueBox.parentNode) valueBox.parentNode.removeChild(valueBox);
    if (timer.parentNode) timer.parentNode.removeChild(timer);
    labelEl.style.display = '';
    revealBtn.textContent = 'Reveal';
    revealBtn.dataset.state = 'reveal';
    revealBtn.disabled = false;
    if (activeRevealCleanup === cleanup) {
      activeRevealCleanup = null;
    }
  }

  activeRevealCleanup = cleanup;

  tick();
  intervalId = setInterval(tick, 1000);
}

// Lock the vault and return to the Unlock screen. Shared by the manual Lock
// button and the idle auto-lock timer, so any future cleanup that should run
// on lock belongs here, not in either caller.
async function performLock() {
  stopIdleTimer();
  try {
    await window.vault.lock();
  } catch (err) {
    console.error('[Renderer] Lock error:', err);
  }
  // Hide any revealed value before changing screens
  if (typeof activeRevealCleanup === 'function') {
    activeRevealCleanup();
  }
  showScreen('unlock');
  // Clear any stale permission state when locking
  hidePermissionDialog();
  // Clear any agent registration/credentials state
  if (typeof hideRegisterModal === 'function') {
    hideRegisterModal();
  }
  oneTimeVaultApiKey = null;
  if (credentialApiKey) {
    credentialApiKey.value = '';
    credentialApiKey.removeAttribute('value');
  }
  if (agentCredentialsOverlay) {
    agentCredentialsOverlay.classList.remove('active');
  }
}

btnLock.addEventListener('click', performLock);

// Navigate to Add Item screen
btnAddItem.addEventListener('click', () => {
  clearAddForm();
  showScreen('add-item');
});

// Navigate to Audit Log screen
btnOpenAudit.addEventListener('click', () => {
  showScreen('audit');
  loadAuditLog();
});


// ---------------------------------------------------------------------------
// SCREEN 3: ADD ITEM
// ---------------------------------------------------------------------------

const addCategory = document.getElementById('add-category');
const addLabel = document.getElementById('add-label');
const addValue = document.getElementById('add-value');
const addError = document.getElementById('add-error');
const btnSaveItem = document.getElementById('btn-save-item');
const btnBackFromAdd = document.getElementById('btn-back-from-add');

// Hardcoded category dropdown options list to prevent dynamic population
const CATEGORY_OPTIONS = ["API KEY", "URL", "ID"];
function initCategoryDropdown() {
  if (!addCategory) return;
  addCategory.innerHTML = '';
  CATEGORY_OPTIONS.forEach(optVal => {
    const opt = document.createElement('option');
    opt.value = optVal;
    opt.textContent = optVal;
    addCategory.appendChild(opt);
  });
}

/**
 * Resets all fields in the Add Item form.
 */
function clearAddForm() {
  addCategory.value = 'API KEY';
  addLabel.value = '';
  addValue.value = '';
  addError.textContent = '';
}

/**
 * Validates the form, sends the new item to the backend, then returns
 * to the dashboard. The plaintext value is only in transit here — the
 * main process encrypts it via the FastAPI endpoint immediately.
 */
async function handleSaveItem() {
  addError.textContent = '';

  const category = addCategory.value.trim();
  const label = addLabel.value.trim();
  const value = addValue.value;

  if (!label) {
    addError.textContent = 'Label is required.';
    addLabel.focus();
    return;
  }
  if (!value) {
    addError.textContent = 'Secret value is required.';
    addValue.focus();
    return;
  }

  btnSaveItem.disabled = true;
  btnSaveItem.textContent = 'Saving…';

  try {
    await window.vault.addItem({ category, label, value });
    clearAddForm();
    showScreen('dashboard');
    loadDashboard();
  } catch (err) {
    // The error message from the main process (e.g. "409 Conflict — label exists")
    addError.textContent = err.message || 'Failed to save. Label may already exist.';
    console.error('[Renderer] addItem error:', err);
  } finally {
    btnSaveItem.disabled = false;
    btnSaveItem.textContent = 'Save Secret';
  }
}

btnSaveItem.addEventListener('click', handleSaveItem);
btnBackFromAdd.addEventListener('click', () => {
  clearAddForm();
  showScreen('dashboard');
});


// ---------------------------------------------------------------------------
// SCREEN 4: PERMISSION DIALOG
// ---------------------------------------------------------------------------

const permissionOverlay = document.getElementById('permission-overlay');
const permAgentId = document.getElementById('perm-agent-id');
const permActionText = document.getElementById('perm-action-text');
const permCountdown = document.getElementById('perm-countdown');
const btnApprove = document.getElementById('btn-approve-perm');
const btnDeny = document.getElementById('btn-deny-perm');

/**
 * Clears any running countdown timer.
 */
function clearCountdownTimer() {
  if (permCountdownInterval !== null) {
    clearInterval(permCountdownInterval);
    permCountdownInterval = null;
  }
}

/**
 * Hides the permission overlay and resets all state.
 */
function hidePermissionDialog() {
  clearCountdownTimer();
  permissionOverlay.classList.remove('active');
  activePermissionRequestId = null;
  permAgentId.textContent = '';
  permActionText.textContent = '';
  permCountdown.textContent = '60s';
}

/**
 * Shows the permission request dialog.
 * Called from the onPermissionRequest listener whenever the main process
 * pushes a new pending permission request from a connected agent.
 *
 * @param {{ request_id: string, action: string, agent_id: string }} data
 */
function showPermissionDialog(data) {
  // If there's already one active, replace it — latest request wins
  clearCountdownTimer();

  activePermissionRequestId = data.request_id;
  permAgentId.textContent = data.agent_id || 'Unknown Agent';
  permActionText.textContent = data.action || 'Unspecified action';

  let remaining = 60;
  permCountdown.textContent = `${remaining}s`;

  permissionOverlay.classList.add('active');

  // Start the 60-second countdown — auto-deny on expiry
  permCountdownInterval = setInterval(() => {
    remaining -= 1;
    permCountdown.textContent = `${remaining}s`;
    if (remaining <= 0) {
      handleDenyPermission();
    }
  }, 1000);
}

async function handleApprovePermission() {
  if (!activePermissionRequestId) return;
  const id = activePermissionRequestId;
  hidePermissionDialog();
  try {
    await window.vault.respondToPermission(id, true);
  } catch (err) {
    console.error('[Renderer] approvePermission error:', err);
  }
}

async function handleDenyPermission() {
  if (!activePermissionRequestId) return;
  const id = activePermissionRequestId;
  hidePermissionDialog();
  try {
    await window.vault.respondToPermission(id, false);
  } catch (err) {
    console.error('[Renderer] denyPermission error:', err);
  }
}

btnApprove.addEventListener('click', handleApprovePermission);
btnDeny.addEventListener('click', handleDenyPermission);

// Register the listener for push notifications from the Electron main process.
// The main process polls /pending_permissions every 2 seconds and sends
// 'permission:incoming' events to this renderer when new requests arrive.
window.vault.onPermissionRequest((data) => {
  showPermissionDialog(data);
});


// ---------------------------------------------------------------------------
// SCREEN 5: AUDIT LOG
// ---------------------------------------------------------------------------

const auditContainer = document.getElementById('audit-container');
const btnBackFromAudit = document.getElementById('btn-back-from-audit');

/**
 * Formats a Unix epoch timestamp (seconds) into a readable local time string.
 * e.g. "22 May 2026, 16:45:03"
 *
 * @param {number} ts - Unix timestamp in seconds
 * @returns {string}
 */
function formatTimestamp(ts) {
  const d = new Date(ts * 1000);
  return d.toLocaleString('en-GB', {
    day: '2-digit',
    month: 'short',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
  });
}

/**
 * Maps a result string to a badge CSS class.
 * Handles compound results like "denied_invalid_signature".
 *
 * @param {string} result
 * @returns {string} CSS class name
 */
function resultBadgeClass(result) {
  if (!result) return 'badge-pending';
  if (result.startsWith('denied')) return 'badge-denied';
  if (result === 'approved' || result === 'success') return 'badge-success';
  return 'badge-pending';
}

/**
 * Makes result strings human-readable for the UI.
 *
 * @param {string} result
 * @returns {string}
 */
function formatResult(result) {
  if (!result) return '—';
  return result.replace(/_/g, ' ');
}

/**
 * Makes action strings human-readable for the UI.
 *
 * @param {string} action
 * @returns {string}
 */
function formatAction(action) {
  if (!action) return '—';
  const labels = {
    'unlock': 'Unlocked vault',
    'lock': 'Locked vault',
    'add_item': 'Added secret',
    'delete_item': 'Deleted secret',
    'request_key': 'Key requested',
    'request_permission': 'Permission request',
    'register_agent': 'Agent registered',
    'revoke_card': 'Card revoked',
  };
  return labels[action] || action.replace(/_/g, ' ');
}

/**
 * Fetches and renders audit log entries.
 * Entries come newest-first from the API.
 */
async function loadAuditLog() {
  auditContainer.innerHTML = '';

  try {
    // The vault.getItems call goes through the IPC proxy in main.js
    // For the audit log, we need a separate IPC call — but since we have
    // no dedicated IPC handler for audit, we call via getItems then navigate.
    // The audit endpoint is GET /api/v1/vault/audit (already built in vault.py).
    // We add a getAudit call to the main process proxy via a new handler below.
    const data = await window.vault.getAudit();
    const entries = data && data.entries ? data.entries : [];

    if (entries.length === 0) {
      const empty = document.createElement('div');
      empty.className = 'empty-state';
      empty.textContent = 'No audit entries yet.';
      auditContainer.appendChild(empty);
      return;
    }

    entries.forEach(entry => {
      const el = document.createElement('div');
      el.className = 'audit-entry';

      const row1 = document.createElement('div');
      row1.className = 'audit-row-1';

      const time = document.createElement('span');
      time.className = 'audit-time';
      time.textContent = formatTimestamp(entry.timestamp);

      const badge = document.createElement('span');
      badge.className = `audit-badge ${resultBadgeClass(entry.result)}`;
      badge.textContent = formatResult(entry.result);

      row1.appendChild(time);
      row1.appendChild(badge);

      const action = document.createElement('p');
      action.className = 'audit-action';
      action.textContent = formatAction(entry.action);

      el.appendChild(row1);
      el.appendChild(action);

      if (entry.agent_id) {
        const agent = document.createElement('p');
        agent.className = 'audit-agent';
        agent.textContent = `Agent: ${entry.agent_id}`;
        el.appendChild(agent);
      }

      if (entry.label_accessed) {
        const target = document.createElement('p');
        target.className = 'audit-target';
        target.textContent = `Label: ${entry.label_accessed}`;
        el.appendChild(target);
      }

      auditContainer.appendChild(el);
    });

  } catch (err) {
    const errMsg = document.createElement('div');
    errMsg.className = 'empty-state';
    errMsg.textContent = 'Failed to load audit log.';
    auditContainer.appendChild(errMsg);
    console.error('[Renderer] loadAuditLog error:', err);
  }
}

btnBackFromAudit.addEventListener('click', () => {
  showScreen('dashboard');
});

// ---------------------------------------------------------------------------
// SCREEN 6: AGENTS MANAGEMENT
// ---------------------------------------------------------------------------

const btnOpenAgents = document.getElementById('btn-open-agents');
const btnBackFromAgents = document.getElementById('btn-back-from-agents');
const btnAddAgent = document.getElementById('btn-add-agent');
const agentsContainer = document.getElementById('agents-container');
const agentsEmptyState = document.getElementById('agents-empty-state');

// Modal Elements
const agentRegisterOverlay = document.getElementById('agent-register-overlay');
const btnCloseRegister = document.getElementById('btn-close-register');
const registerAgentId = document.getElementById('register-agent-id');
const registerPermissionsList = document.getElementById('register-permissions-list');
const registerTtl = document.getElementById('register-ttl');
const registerError = document.getElementById('register-error');
const btnSubmitRegister = document.getElementById('btn-submit-register');

const agentCredentialsOverlay = document.getElementById('agent-credentials-overlay');
const credentialApiKey = document.getElementById('credential-api-key');
const btnCopyApiKey = document.getElementById('btn-copy-api-key');
const btnConfirmCredentials = document.getElementById('btn-confirm-credentials');

// Temporary memory to hold the raw generated key until it is purged
let oneTimeVaultApiKey = null;

// Route navigation to Agents screen
btnOpenAgents.addEventListener('click', () => {
  showScreen('agents');
  loadAgents();
});

btnBackFromAgents.addEventListener('click', () => {
  showScreen('dashboard');
});

// Close Register Modal
btnCloseRegister.addEventListener('click', () => {
  hideRegisterModal();
});

function hideRegisterModal() {
  agentRegisterOverlay.classList.remove('active');
  registerAgentId.value = '';
  registerPermissionsList.innerHTML = '';
  registerTtl.value = '1';
  registerError.textContent = '';
}

// Open Register Modal (and dynamically populate permissions)
btnAddAgent.addEventListener('click', async () => {
  registerPermissionsList.innerHTML = '';
  registerAgentId.value = '';
  registerError.textContent = '';
  registerTtl.value = '1';

  try {
    const data = await window.vault.getItems();
    const items = data && data.items ? data.items : [];

    if (items.length === 0) {
      const msg = document.createElement('div');
      msg.style.fontSize = '11px';
      msg.style.color = 'var(--dim)';
      msg.textContent = 'No secrets available to share.';
      registerPermissionsList.appendChild(msg);
    } else {
      // Sort items by label
      items.sort((a, b) => a.label.localeCompare(b.label));

      items.forEach(item => {
        const row = document.createElement('label');
        const checkbox = document.createElement('input');
        checkbox.type = 'checkbox';
        checkbox.value = item.label;
        checkbox.className = 'perm-checkbox';

        const span = document.createElement('span');
        span.textContent = item.label;

        row.appendChild(checkbox);
        row.appendChild(span);
        registerPermissionsList.appendChild(row);
      });
    }

    agentRegisterOverlay.classList.add('active');
    registerAgentId.focus();
  } catch (err) {
    registerError.textContent = 'Failed to load secrets list.';
    console.error('[Renderer] Error loading permissions checkboxes:', err);
  }
});

// Submit New Agent Registration
btnSubmitRegister.addEventListener('click', async () => {
  registerError.textContent = '';
  const agentId = registerAgentId.value.trim();
  const ttlVal = registerTtl.value;
  const ttlHours = ttlVal === 'never' ? null : parseInt(ttlVal, 10);

  if (!agentId) {
    registerError.textContent = 'Agent Name / ID is required.';
    registerAgentId.focus();
    return;
  }

  // Collect checked permission labels
  const permissions = [];
  document.querySelectorAll('.perm-checkbox:checked').forEach(cb => {
    permissions.push(cb.value);
  });

  btnSubmitRegister.disabled = true;
  btnSubmitRegister.textContent = 'Registering…';

  try {
    // Exact field names accepted by POST /agent/register: agent_id, permissions, ttl_hours
    const response = await window.vault.registerAgent({
      agent_id: agentId,
      permissions: permissions,
      ttl_hours: ttlHours
    });

    if (response && response.vault_api_key) {
      // Store the key in temporary memory and render on screen
      oneTimeVaultApiKey = response.vault_api_key;
      credentialApiKey.value = oneTimeVaultApiKey;

      // Hide the form modal and show the credentials screen
      hideRegisterModal();
      agentCredentialsOverlay.classList.add('active');
    } else {
      registerError.textContent = 'Failed to generate key.';
    }
  } catch (err) {
    registerError.textContent = err.message || 'Failed to register agent.';
    console.error('[Renderer] registerAgent error:', err);
  } finally {
    btnSubmitRegister.disabled = false;
    btnSubmitRegister.textContent = 'Create Agent';
  }
});

// One-Time Credentials Copy Button
btnCopyApiKey.addEventListener('click', async () => {
  if (!oneTimeVaultApiKey) return;

  try {
    await navigator.clipboard.writeText(oneTimeVaultApiKey);
    btnCopyApiKey.textContent = 'Copied!';
    setTimeout(() => {
      btnCopyApiKey.textContent = 'Copy';
    }, 2000);
  } catch (err) {
    console.error('[Renderer] Clipboard copy failed:', err);
  }
});

// Confirm Credentials Saved (Purges Key from Renderer Memory)
btnConfirmCredentials.addEventListener('click', () => {
  // CRITICAL SECURITY WIPE: Purge raw key from variables and the DOM
  oneTimeVaultApiKey = null;
  credentialApiKey.value = '';
  credentialApiKey.removeAttribute('value');

  // Hide modal and reload lists
  agentCredentialsOverlay.classList.remove('active');
  loadAgents();
});

// Load Registered Agents List
async function loadAgents() {
  agentsContainer.innerHTML = '';

  try {
    const agents = await window.vault.listAgents();

    if (!agents || agents.length === 0) {
      agentsContainer.appendChild(agentsEmptyState);
      return;
    }

    const now = Math.floor(Date.now() / 1000);

    agents.forEach(agent => {
      const card = document.createElement('div');
      card.className = 'agent-card';
      if (agent.is_expired) {
        card.classList.add('expired');
      }

      const header = document.createElement('div');
      header.className = 'agent-card-header';

      const name = document.createElement('span');
      name.className = 'agent-card-name';
      name.textContent = agent.agent_name;

      const ttl = document.createElement('span');
      ttl.className = 'agent-card-ttl';

      if (agent.valid_until === null) {
        ttl.textContent = 'No expiry';
        ttl.style.color = 'var(--dim)';
      } else if (agent.is_expired) {
        ttl.textContent = 'Expired';
      } else {
        const diffSeconds = agent.valid_until - now;
        if (diffSeconds <= 0) {
          ttl.textContent = 'Expired';
        } else {
          const diffHours = Math.ceil(diffSeconds / 3600);
          ttl.textContent = `Expires in ${diffHours}h`;
        }
      }

      header.appendChild(name);
      header.appendChild(ttl);
      card.appendChild(header);

      // Permissions badges
      const permsDiv = document.createElement('div');
      permsDiv.className = 'agent-card-permissions';

      if (agent.allowed_labels && agent.allowed_labels.length > 0) {
        agent.allowed_labels.forEach(label => {
          const badge = document.createElement('span');
          badge.className = 'agent-card-permission-badge';
          badge.textContent = label;
          permsDiv.appendChild(badge);
        });
      } else {
        const badge = document.createElement('span');
        badge.className = 'agent-card-permission-badge';
        badge.style.fontStyle = 'italic';
        badge.textContent = 'No permissions';
        permsDiv.appendChild(badge);
      }
      card.appendChild(permsDiv);

      // Actions (Revoke Button)
      const actionsDiv = document.createElement('div');
      actionsDiv.className = 'agent-card-actions';

      const revokeBtn = document.createElement('button');
      revokeBtn.className = 'btn-revoke';
      revokeBtn.textContent = 'Revoke';
      revokeBtn.type = 'button';
      revokeBtn.addEventListener('click', () => {
        handleRevokeAgent(agent.card_id, agent.agent_name);
      });

      actionsDiv.appendChild(revokeBtn);
      card.appendChild(actionsDiv);

      agentsContainer.appendChild(card);
    });

  } catch (err) {
    agentsContainer.innerHTML = '';
    const errMsg = document.createElement('div');
    errMsg.className = 'empty-state';
    errMsg.textContent = 'Failed to load agents list.';
    agentsContainer.appendChild(errMsg);
    console.error('[Renderer] loadAgents error:', err);
  }
}

// Revoke Agent confirmation and execution
async function handleRevokeAgent(cardId, name) {
  if (!confirm(`Revoke agent "${name}"?\n\nThis is permanent and will immediately disable all access for this agent.`)) {
    return;
  }

  try {
    await window.vault.revokeAgent(cardId);
    loadAgents();
  } catch (err) {
    alert(`Failed to revoke agent: ${err.message || err}`);
    console.error('[Renderer] revokeAgent error:', err);
  }
}

// ---------------------------------------------------------------------------
// SETUP FLOW
// ---------------------------------------------------------------------------
const setupPasswordInput = document.getElementById('setup-password');
const setupConfirmPasswordInput = document.getElementById('setup-confirm-password');
const strengthLabel = document.getElementById('strength-label');
const strengthBar = document.getElementById('strength-bar');
const setupBtn = document.getElementById('setup-btn');
const setupError = document.getElementById('setup-error');

function checkPasswordStrength(password) {
  if (!password) {
    return { label: 'Too short', color: 'var(--danger)', width: '0%' };
  }
  const len = password.length;
  if (len < 8) {
    return { label: 'Too short', color: 'var(--danger)', width: '25%' };
  } else if (len >= 8 && len <= 11) {
    return { label: 'Weak', color: '#F97316', width: '50%' };
  } else if (len >= 12 && len <= 15) {
    return { label: 'Fair', color: '#FBBF24', width: '75%' };
  } else {
    return { label: 'Strong', color: 'var(--accent)', width: '100%' };
  }
}

function updateSetupValidation() {
  const password = setupPasswordInput.value;
  const confirmPassword = setupConfirmPasswordInput.value;

  const strength = checkPasswordStrength(password);
  strengthLabel.textContent = strength.label;
  strengthBar.style.width = strength.width;
  strengthBar.style.backgroundColor = strength.color;

  if (password.length >= 8 && password === confirmPassword) {
    setupBtn.disabled = false;
    setupError.textContent = '';
  } else {
    setupBtn.disabled = true;
    if (password && confirmPassword && password !== confirmPassword) {
      setupError.textContent = 'Passwords do not match.';
    } else {
      setupError.textContent = '';
    }
  }
}

setupPasswordInput.addEventListener('input', updateSetupValidation);
setupConfirmPasswordInput.addEventListener('input', updateSetupValidation);

async function handleSetup() {
  setupError.textContent = '';
  const password = setupPasswordInput.value;

  setupBtn.disabled = true;
  setupBtn.textContent = 'Creating Vault…';

  try {
    const result = await window.vault.setup(password);
    if (result && result.success) {
      const recoveryCode = result.recovery_code;
      setupPasswordInput.value = '';
      setupConfirmPasswordInput.value = '';
      showRecoveryScreen(recoveryCode);
    } else {
      setupError.textContent = result.error || 'Setup failed.';
    }
  } catch (err) {
    setupError.textContent = 'Could not initialize vault.';
    console.error('[Renderer] Setup error:', err);
  } finally {
    setupBtn.disabled = false;
    setupBtn.textContent = 'Create Vault';
  }
}

setupBtn.addEventListener('click', handleSetup);
setupPasswordInput.addEventListener('keydown', (e) => {
  if (e.key === 'Enter' && !setupBtn.disabled) handleSetup();
});
setupConfirmPasswordInput.addEventListener('keydown', (e) => {
  if (e.key === 'Enter' && !setupBtn.disabled) handleSetup();
});

// ---------------------------------------------------------------------------
// RECOVERY DISPLAY FLOW
// ---------------------------------------------------------------------------
const recoveryCodeDisplay = document.getElementById('recovery-code-display');
const btnCopyRecoveryCode = document.getElementById('btn-copy-recovery-code');
const chkSavedCode = document.getElementById('chk-saved-code');
const btnContinueToVault = document.getElementById('btn-continue-to-vault');

function showRecoveryScreen(code) {
  recoveryCodeDisplay.value = code;
  chkSavedCode.checked = false;
  btnContinueToVault.disabled = true;
  showScreen('recovery-code');
}

btnCopyRecoveryCode.addEventListener('click', async () => {
  const code = recoveryCodeDisplay.value;
  if (!code) return;
  try {
    await navigator.clipboard.writeText(code);
    btnCopyRecoveryCode.textContent = 'Copied!';
    setTimeout(() => {
      btnCopyRecoveryCode.textContent = 'Copy';
    }, 2000);
  } catch (err) {
    console.error('[Renderer] Clipboard copy failed:', err);
  }
});

chkSavedCode.addEventListener('change', () => {
  btnContinueToVault.disabled = !chkSavedCode.checked;
});

btnContinueToVault.addEventListener('click', () => {
  showScreen('dashboard');
  loadDashboard();
  startIdleTimer();
});

// ---------------------------------------------------------------------------
// FORGOT PASSWORD FLOW
// ---------------------------------------------------------------------------
const forgotPasswordLink = document.getElementById('forgot-password-link');
const backToUnlockLink = document.getElementById('back-to-unlock-link');
const forgotRecoveryCodeInput = document.getElementById('forgot-recovery-code');
const forgotNewPasswordInput = document.getElementById('forgot-new-password');
const forgotConfirmPasswordInput = document.getElementById('forgot-confirm-password');
const forgotBtn = document.getElementById('forgot-btn');
const forgotError = document.getElementById('forgot-error');

forgotPasswordLink.addEventListener('click', (e) => {
  e.preventDefault();
  forgotRecoveryCodeInput.value = '';
  forgotNewPasswordInput.value = '';
  forgotConfirmPasswordInput.value = '';
  forgotError.textContent = '';
  showScreen('recover');
});

backToUnlockLink.addEventListener('click', (e) => {
  e.preventDefault();
  unlockPasswordInput.value = '';
  clearUnlockError();
  showScreen('unlock');
});

async function handleRecover() {
  forgotError.textContent = '';
  const recovery_code = forgotRecoveryCodeInput.value.trim();
  const new_password = forgotNewPasswordInput.value;
  const confirmPassword = forgotConfirmPasswordInput.value;

  if (!recovery_code) {
    forgotError.textContent = 'Enter your recovery code.';
    forgotRecoveryCodeInput.focus();
    return;
  }
  if (!new_password) {
    forgotError.textContent = 'Enter a new master password.';
    forgotNewPasswordInput.focus();
    return;
  }
  if (new_password.length < 8) {
    forgotError.textContent = 'Password must be at least 8 characters.';
    forgotNewPasswordInput.focus();
    return;
  }
  if (new_password !== confirmPassword) {
    forgotError.textContent = 'Passwords do not match.';
    forgotConfirmPasswordInput.focus();
    return;
  }

  forgotBtn.disabled = true;
  forgotBtn.textContent = 'Recovering…';

  try {
    const result = await window.vault.recover({ recovery_code, new_password });
    if (result && result.success) {
      const newRecoveryCode = result.new_recovery_code;
      forgotRecoveryCodeInput.value = '';
      forgotNewPasswordInput.value = '';
      forgotConfirmPasswordInput.value = '';
      showRecoveryScreen(newRecoveryCode);
    } else {
      forgotError.textContent = 'Invalid recovery code';
    }
  } catch (err) {
    forgotError.textContent = 'Invalid recovery code';
    console.error('[Renderer] Recovery error:', err);
  } finally {
    forgotBtn.disabled = false;
    forgotBtn.textContent = 'Recover Vault';
  }
}

forgotBtn.addEventListener('click', handleRecover);

forgotRecoveryCodeInput.addEventListener('keydown', (e) => {
  if (e.key === 'Enter') handleRecover();
});
forgotNewPasswordInput.addEventListener('keydown', (e) => {
  if (e.key === 'Enter') handleRecover();
});
forgotConfirmPasswordInput.addEventListener('keydown', (e) => {
  if (e.key === 'Enter') handleRecover();
});

// ---------------------------------------------------------------------------
// INITIALIZATION
// ---------------------------------------------------------------------------
async function init() {
  initCategoryDropdown();
  try {
    const isFirst = await window.vault.isFirstRun();
    if (isFirst) {
      showScreen('setup');
    } else {
      showScreen('unlock');
    }
  } catch (err) {
    console.error('[Renderer] Initialization error:', err);
    showScreen('unlock'); // fallback
  }
}

init();
