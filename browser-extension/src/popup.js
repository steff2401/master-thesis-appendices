import { DEFAULT_FLAG_CONFIG, FLAG_LABELS } from './flags.js';

// Helper to create an HTML element with class and text content if provided
function makeElement(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text) node.textContent = text;
  return node;
}

// Helper to clone a <template> element by ID and return its first child
// Used to generate the flag tables and rows, and the virtual credential rows
function cloneTemplate(id) {
  return document.getElementById(id).content.firstElementChild.cloneNode(true);
}

// Order the fields in the output as the spec defines them
const fieldOrder = {
  options: ['rp', 'user', 'challenge', 'pubKeyCredParams', 'timeout', 'excludeCredentials', 'authenticatorSelection', 'attestation', 'rpId', 'allowCredentials', 'userVerification', 'extensions', 'hints'],
  credential: ['id', 'rawId', 'response', 'authenticatorAttachment', 'type', 'clientExtensionResults'],
  rp: ['id', 'name'],
  user: ['id', 'name', 'displayName'],
  authenticatorSelection: ['authenticatorAttachment', 'residentKey', 'requireResidentKey', 'userVerification'],
  response: ['clientDataJSON', 'attestationObject', 'authenticatorData', 'signature', 'userHandle'],
  authData: ['rpIdHash', 'flags', 'signatureCounter', 'aaguid', 'credentialId', 'credentialPublicKey'],
  attestationObject: ['fmt', 'attStmt', 'authData'],
  attStmt: ['alg', 'sig', 'attestationType', 'x5c']
};

// Reorders the fields accoring to fieldOrder above
function orderedReplacer(key, value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return value;

  let order = fieldOrder[key];
  if (!order) order = fieldOrder.options;

  // First, add the fields in the order specified by fieldOrder
  const ordered = {};
  for (const field of order) {
    if (field in value) ordered[field] = value[field];
  }

  // Then, add any remaining fields in the order they appear in the object
  for (const field in value) {
    if (!(field in ordered)) ordered[field] = value[field];
  }

  return ordered;
}

// Magically adds syntax highlighting to JSON by wrapping the different types in <span> elements with classes
function syntaxHighlightJSON(json) {
  const pre = makeElement('pre');
  // The regex is from https://stackoverflow.com/a/7220510/10629172
  const regex = /("(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d*)?(?:[eE][+\-]?\d+)?)/g;
  // Where the previous token ended, so we know which bit of plain text comes before the next one
  let lastIndex = 0;

  // Go through every token in the order they appear
  for (const match of json.matchAll(regex)) {
    const token = match[0];

    // Anything between the last token and this one is plain text
    if (match.index > lastIndex) pre.append(json.slice(lastIndex, match.index));

    // Figure out what kind of token this is. If it's not a string, boolean or null it has to be a number
    let tokenType = 'number';
    if (token.startsWith('"')) {
      // The regex pulls the ':' into a key's token, which is what tells the two apart. A string value may contain one of its own (origins, timestamps)
      if (token.endsWith(':')) tokenType = 'key';
      else tokenType = 'string';
    }
    else if (token === 'true' || token === 'false') tokenType = 'boolean';
    else if (token === 'null') tokenType = 'null';

    // Wrap the token in a span with a class like json-key or json-string, popup.css applies the colours
    pre.append(makeElement('span', 'json-' + tokenType, token));

    lastIndex = match.index + token.length;
  }

  // Plain text after the last token (usually just the closing brackets)
  if (lastIndex < json.length) pre.append(json.slice(lastIndex));

  return pre;
}

// Gets the logs from storage, or an empty array if there are none
async function getLogs() {
  const stored = await chrome.storage.local.get('webauthn_logs');
  return stored.webauthn_logs || [];
}

// Displays the logs in the popup, or a message if there are none
async function displayLogs() {
  const logs = await getLogs();
  const logList = document.getElementById('logs');

  logList.textContent = '';
  // Show the "no logs" message if there are no logs, hide the message if there are
  document.getElementById('logs-empty').hidden = logs.length > 0;

  if (logs.length === 0) return;

  for (const log of logs) {
    const isVirtual = Boolean(log.data?.credential?._virtual);
    const type = makeElement('span', 'log-type', log.type);
    if (isVirtual) type.append(makeElement('span', 'virtual-active-badge', 'VIRTUAL'));

    const time = new Date(log.timestamp).toLocaleString('no-NO');
    const header = makeElement('div', 'log-header');
    header.append(type, makeElement('span', 'log-time', time));

    const entryClass = isVirtual ? 'log-entry virtual' : 'log-entry';

    const entry = makeElement('div', entryClass);
    entry.append(header, makeElement('div', 'log-url', log.url), syntaxHighlightJSON(JSON.stringify(log.data, orderedReplacer, 2)));

    logList.append(entry);
  }
}

// Downloads the logs as a JSON file
async function exportLogs() {
  const logs = await getLogs();
  if (logs.length === 0) return;

  const blob = new Blob([JSON.stringify(logs, orderedReplacer, 2)], { type: 'application/json' });
  const link = document.createElement('a');
  link.href = URL.createObjectURL(blob);
  link.download = 'webauthn-logs-' + Date.now() + '.json';
  link.click();
}

// When the user changes a flag setting, save the new config to storage. The UI will be updated automatically by the storage.onChanged listener in init()
function saveFlagConfig() {
  const config = { create: {}, get: {} };

  const selects = document.querySelectorAll('[data-flag][data-operation]');
  for (const select of selects) {
    const operation = select.dataset.operation;
    const flag = select.dataset.flag;
    config[operation][flag] = select.value === 'on';
  }

  chrome.storage.local.set({ webauthn_flag_config: config });
}

// When the popup opens, read the stored config and apply it to the UI. If there is no stored config, use the default values
function applyFlagConfigToUI(config) {
  const selects = document.querySelectorAll('[data-flag][data-operation]');

  for (const select of selects) {
    const operation = select.dataset.operation;
    const flag = select.dataset.flag;

    // Fall back to the default value if there is no stored config for this operation and flag
    let value = DEFAULT_FLAG_CONFIG[operation][flag];
    if (config?.[operation] && flag in config[operation]) value = config[operation][flag];

    select.value = value ? 'on' : 'off';
  }
}

// Builds a table of flag settings for the given operation (create or get)
function buildFlagTable(operation) {
  const table = cloneTemplate('flag-table-template');
  const body = table.querySelector('tbody');

  for (const flag in FLAG_LABELS) {
    const row = cloneTemplate('flag-row-template');
    row.querySelector('.flag-label').textContent = FLAG_LABELS[flag];

    const select = row.querySelector('select');
    select.dataset.flag = flag;
    select.dataset.operation = operation;
    select.value = DEFAULT_FLAG_CONFIG[operation][flag] ? 'on' : 'off';
    select.addEventListener('change', saveFlagConfig);

    body.append(row);
  }

  return table;
}

// Enables or disables the flag settings section based on whether the virtual authenticator is enabled
function setFlagSettingsEnabled(enabled) {
  const section = document.getElementById('flag-settings-section');
  section.classList.toggle('flag-settings-disabled', !enabled);
}

// Gets the virtual credentials from storage, or an empty array if there are none
async function getAllCredentials() {
  const stored = await chrome.storage.local.get('webauthn_virtual_credentials');
  return stored.webauthn_virtual_credentials || [];
}

// Deletes a virtual credential by its ID and updates storage
async function deleteCredential(credentialId) {
  // The credential is deleted by filtering it out of the array and saving the remaining credentials back to storage
  const credentials = await getAllCredentials();
  const remaining = [];

  for (const credential of credentials) {
    if (credential.credentialId === credentialId) continue;
    remaining.push(credential);
  }

  await chrome.storage.local.set({ webauthn_virtual_credentials: remaining });
}

// Displays the virtual credentials in the popup, or a message if there are none
async function displayCredentials() {
  const credentialList = document.getElementById('virtual-credentials-list');
  const credentials = await getAllCredentials();

  credentialList.textContent = '';
  document.getElementById('virtual-credentials-empty').hidden = credentials.length > 0;

  if (credentials.length === 0) return;

  for (const cred of credentials) {
    const id = makeElement('span', 'virtual-cred-id', cred.credentialId.slice(0, 12) + '…');
    id.title = cred.credentialId;

    const created = new Date(cred.createdAt).toLocaleString('no-NO');
    const userName = cred.userName || '(no user)';
    const details = cred.rpId + '  ·  ' + userName + '  ·  counter: ' + cred.signCount + '  ·  ' + created;

    const info = makeElement('div', 'virtual-cred-info');
    info.append(id, makeElement('span', 'virtual-cred-details', details));

    const remove = makeElement('button', 'virtual-cred-delete', '✕');
    remove.title = 'Delete credential';
    remove.addEventListener('click', function () {
      deleteCredential(cred.credentialId);
    });

    const row = makeElement('div', 'virtual-cred-row');
    row.append(info, remove);
    credentialList.append(row);
  }
}

// Initializes the popup by setting up event listeners, reading stored settings, and displaying logs and credentials
async function init() {
  const isExpanded = new URLSearchParams(location.search).has('expanded');
  document.body.classList.add(isExpanded ? 'expanded' : 'popup');

  document.getElementById('clear').addEventListener('click', function () {
    chrome.storage.local.set({ webauthn_logs: [] });
  });
  document.getElementById('export').addEventListener('click', exportLogs);

  // The button either opens a new window with the expanded popup, or closes the current window if it's already expanded
  const windowButton = document.getElementById('window-button');
  if (isExpanded) {
    windowButton.textContent = 'Close Window';
    windowButton.addEventListener('click', function () {
      window.close();
    });
  } else {
    windowButton.textContent = 'Open Window';
    windowButton.addEventListener('click', function () {
      chrome.windows.create({ url: chrome.runtime.getURL('static/popup.html?expanded=1'), type: 'normal', width: 1200, height: 700 });
      window.close();
    });
  }

  const flagFields = document.getElementById('flag-settings-fields');
  for (const operation in DEFAULT_FLAG_CONFIG) {
    flagFields.append(makeElement('div', 'flag-settings-op-title', operation));
    flagFields.append(buildFlagTable(operation));
  }

  const virtualEnabled = document.getElementById('virtual-enabled');
  virtualEnabled.addEventListener('change', function () {
    chrome.storage.local.set({ webauthn_virtual_authenticator_enabled: virtualEnabled.checked });
    setFlagSettingsEnabled(virtualEnabled.checked);
  });

  // Listen for changes to the logs and credentials in storage, and update the UI accordingly
  chrome.storage.onChanged.addListener(function (changes) {
    if (changes.webauthn_logs) displayLogs();
    if (changes.webauthn_virtual_credentials) displayCredentials();
  });

  displayLogs();
  displayCredentials();

  const stored = await chrome.storage.local.get(['webauthn_flag_config', 'webauthn_virtual_authenticator_enabled']);
  applyFlagConfigToUI(stored.webauthn_flag_config);

  virtualEnabled.checked = Boolean(stored.webauthn_virtual_authenticator_enabled);
  setFlagSettingsEnabled(virtualEnabled.checked);
}

init();