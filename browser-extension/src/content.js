// Create script tag to inject injected.js into the web page
const script = document.createElement('script');
script.src = chrome.runtime.getURL('dist/injected.js');

// When the script has loaded and injected injected.js, remove the script tag
script.onload = () => script.remove();

script.onerror = (err) => console.error('[WebAuthn Explorer] Failed to load script:', err);

// Add the script tag to the web page, actually injecting injected.js into the page
// document.head could be null if the page is still loading, so fall back to document.documentElement
(document.head || document.documentElement).prepend(script);

// Forward when user changes config to injected.js
chrome.storage.onChanged.addListener(function (changes) {
  if (changes.webauthn_flag_config) pushConfig('WEBAUTHN_FLAG_CONFIG', changes.webauthn_flag_config.newValue);
  if (changes.webauthn_virtual_authenticator_enabled) pushConfig('WEBAUTHN_VIRTUAL_AUTHENTICATOR_ENABLED', changes.webauthn_virtual_authenticator_enabled.newValue);
});

// Listen for messages from injected.js and the virtual authenticator
window.addEventListener('message', async function (event) {
  // Ignore messages that are not from this window or don't have data
  if (event.source !== window || !event.data) return;

  const type = event.data.type;

  // Only push config when injected.js is ready, otherwise it will be lost
  // injected.js signals that it is ready by sending a WEBAUTHN_EXPLORER_READY message
  if (type === 'WEBAUTHN_EXPLORER_READY') {
    const stored = await chrome.storage.local.get(['webauthn_flag_config', 'webauthn_virtual_authenticator_enabled']);
    pushConfig('WEBAUTHN_FLAG_CONFIG', stored.webauthn_flag_config);
    pushConfig('WEBAUTHN_VIRTUAL_AUTHENTICATOR_ENABLED', stored.webauthn_virtual_authenticator_enabled);
    return;
  }

  // Store events from injected.js in chrome.storage.local
  if (type === 'WEBAUTHN_EVENT') {
    try {
      await storeEvent(event.data.event);
    } catch (error) {
      console.error('[WebAuthn Explorer] Failed to store event:', error);
    }
    return;
  }

  // Handle messages from the virtual authenticator, which are requests to store/get/update credentials
  try {
    let data = null;

    if (type === 'WEBAUTHN_VIRTUAL_STORE_CREDENTIAL') await storeCredential(event.data.credential);
    else if (type === 'WEBAUTHN_VIRTUAL_GET_CREDENTIALS') data = await getMatchingCredentials(event.data.rpId, event.data.allowCredentials);
    else if (type === 'WEBAUTHN_VIRTUAL_UPDATE_SIGCOUNT') await updateSignCount(event.data.credentialId, event.data.signCount);
    else return;

    respondToVirtualAuthenticator(event.data.requestId, true, data, null);
  } catch (error) {
    respondToVirtualAuthenticator(event.data.requestId, false, null, error.message);
  }
});

// For debugging: log that the message listener has been initialized
console.log('[WebAuthn Explorer Content Script] Message listener initialized');

// Helper to send changes in config to injected.js
function pushConfig(type, config) {
  window.postMessage({ type, config }, '*');
}

// Helper to respond to the virtual authenticator with the result of a request
function respondToVirtualAuthenticator(requestId, success, data, error) {
  window.postMessage({ type: 'WEBAUTHN_VIRTUAL_RESPONSE', requestId, success, data, error }, '*');
}

// Store an event in chrome.storage.local
// An event is a log of a WebAuthn operation
async function storeEvent(event) {
  const stored = await chrome.storage.local.get('webauthn_logs');
  const logs = stored.webauthn_logs || []; // default to empty array if nothing stored, to avoid checking for undefined/null later
  logs.push(event);

  // Limit the number of events stored
  if (logs.length > 100) logs.shift();

  await chrome.storage.local.set({ webauthn_logs: logs });
}

// Helper to get all stored credentials from chrome.storage.local
async function getAllCredentials() {
  const stored = await chrome.storage.local.get('webauthn_virtual_credentials');
  return stored.webauthn_virtual_credentials || []; // default to empty array if nothing stored, to avoid checking for undefined/null later
}

// Store a credential in chrome.storage.local
async function storeCredential(credential) {
  const credentials = await getAllCredentials();
  credentials.push(credential);
  await chrome.storage.local.set({ webauthn_virtual_credentials: credentials });
}

// Get the credentials matching a given rpId and allowCredentials list
async function getMatchingCredentials(rpId, allowCredentials) {
  const credentials = await getAllCredentials();
  const matching = [];

  for (const credential of credentials) {
    if (credential.rpId !== rpId) continue;
    // If allowCredentials is provided, only return credentials that are in that list
    if (allowCredentials?.length > 0 && !allowCredentials.includes(credential.credentialId)) continue;
    matching.push(credential);
  }

  return matching;
}

// Update the signCount of a credential in chrome.storage.local
async function updateSignCount(credentialId, signCount) {
  const credentials = await getAllCredentials();

  for (const credential of credentials) {
    if (credential.credentialId === credentialId) {
      credential.signCount = signCount;
      break;
    }
  }

  await chrome.storage.local.set({ webauthn_virtual_credentials: credentials });
}