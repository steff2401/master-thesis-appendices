import { decode as cborDecode, decodeFirst as cborDecodeFirst, encode as cborEncode } from 'cborg';
import { X509, zulutodate, KJUR } from 'jsrsasign';
import { buildFlagByte, describeFlags } from './flags.js';

const LOG_PREFIX = '[WebAuthn Explorer]';

// -7 is the COSE algorithm identifier for ES256, the public key algorithm used by the virtual authenticator. See https://www.iana.org/assignments/cose/cose.xhtml#algorithms
const ES256 = -7;

// These will hold the latest config pushed from content.js
let flagConfig = null;
let virtualAuthenticatorEnabled = false;

const utf8Encoder = new TextEncoder();
const utf8Decoder = new TextDecoder();

// Used to convert a Uint8Array or ArrayBuffer to base64url for logging and storage
function base64urlEncode(buffer) {
  let bytes;

  // A view can sit inside a bigger buffer, so take only its own part
  if (ArrayBuffer.isView(buffer)) bytes = new Uint8Array(buffer.buffer, buffer.byteOffset, buffer.byteLength);
  else bytes = new Uint8Array(buffer);

  return bytes.toBase64({ alphabet: 'base64url', omitPadding: true });
}

// Used to convert base64url back to a Uint8Array for storage and crypto operations
function base64urlDecode(string) {
  return Uint8Array.fromBase64(string, { alphabet: 'base64url' });
}

// Formats 32 hex characters (an AAGUID) as a hyphenated UUID
function formatAsUUID(hex) {
  return hex.slice(0, 8) + '-' + hex.slice(8, 12) + '-' + hex.slice(12, 16) + '-' + hex.slice(16, 20) + '-' + hex.slice(20);
}

// Joins any number of byte arrays into one
function concatBytes(...arrays) {
  let total = 0;
  for (const array of arrays) total += array.length;
  const result = new Uint8Array(total);
  
  let offset = 0;
  for (const array of arrays) {
    result.set(array, offset);
    offset += array.length;
  }

  return result;
}

// SHA-256 of a byte buffer or of a string
async function sha256(input) {
  let bytes = input;
  // crypto.subtle.digest only takes in bytes, so encode strings as UTF-8 first
  if (typeof input === 'string') bytes = utf8Encoder.encode(input);

  const hash = await crypto.subtle.digest('SHA-256', bytes);
  return new Uint8Array(hash);
}

// Packs an EC P-256 public key into a CBOR COSE_Key for storage in the virtual authenticator
function encodeCosePublicKey(x, y) {
  const coseKey = new Map(); // Has to be map for CBOR to encode integer keys correctly
  coseKey.set(1, 2); // kty: EC2
  coseKey.set(3, ES256); // alg
  coseKey.set(-1, 1); // crv: P-256
  coseKey.set(-2, x);
  coseKey.set(-3, y);

  return cborEncode(coseKey);
}

// Parses a DER X.509 certificate into readable fields
function decodeCertificate(derBytes) {
  try {
    const cert = new X509();
    cert.readCertHex(derBytes.toHex());

    return {
      subject: cert.getSubjectString(),
      issuer: cert.getIssuerString(),
      serialNumber: cert.getSerialNumberHex(),
      notBefore: zulutodate(cert.getNotBefore()).toISOString(),
      notAfter: zulutodate(cert.getNotAfter()).toISOString(),
      signatureAlgorithm: cert.getSignatureAlgorithmField(),
      publicKeyInfo: cert.getPublicKey().type
    };
  } catch (error) {
    return { error: error.toString() };
  }
}

// AuthenticatorData layout is in https://www.w3.org/TR/2026/CR-webauthn-3-20260113/#sctn-authenticator-data
function decodeAuthenticatorData(buffer) {
  const bytes = new Uint8Array(buffer);
  const result = {};

  try {
    const view = new DataView(bytes.buffer, bytes.byteOffset);

    // The first 37 bytes are fixed: rpIdHash (32), flags (1), signature counter (4)
    result.rpIdHash = bytes.slice(0, 32).toHex();
    result.flags = describeFlags(bytes[32]);
    result.signatureCounter = view.getUint32(33, false);

    let offset = 37;

    // The rest of the buffer can hold either attested credential data and/or extension data
    if (result.flags.attestedCredentialData) {
      // See https://www.w3.org/TR/2026/CR-webauthn-3-20260113/#sctn-attested-credential-data for the structure of attested credential data

      result.aaguid = formatAsUUID(bytes.slice(offset, offset + 16).toHex());
      offset += 16;

      const idLength = view.getUint16(offset, false);
      offset += 2;

      result.credentialId = base64urlEncode(bytes.slice(offset, offset + idLength));
      offset += idLength;

      // The public key is a COSE_Key, which is a CBOR map with integer keys
      // It has variable length, so decode the first CBOR item and see how many bytes were consumed
      const rest = bytes.slice(offset); // read the rest of the buffer after the credentialId
      const decoded = cborDecodeFirst(rest, { useMaps: true }); // read the first CBOR item, which is be the COSE_Key
      const afterCoseKey = decoded[1]; // the second element of the returned array is the remaining bytes after the COSE_Key
      const coseKeyLength = rest.length - afterCoseKey.length;

      result.credentialPublicKey = base64urlEncode(rest.slice(0, coseKeyLength));
      offset += coseKeyLength;

      // If the extensionData flag is set when the AT flag is set, the rest of the buffer is a CBOR map of extensions
      if (result.flags.extensionData) result.extensions = cborDecode(afterCoseKey);

    } else if (result.flags.extensionData) {
      // Here the AT flag is not set, but the ED flag is set, so the rest of the buffer is a CBOR map of extensions
      const extensionBytes = bytes.slice(offset);
      result.extensions = cborDecode(extensionBytes);
    }
  } catch (error) {
    result.error = error.toString();
  }

  return result;
}

// Parses an attestationObject into { fmt, attStmt, authData }
function decodeAttestationObject(buffer) {
  try {
    const decoded = cborDecode(new Uint8Array(buffer));
    const attStmt = decoded.attStmt;

    if (attStmt?.x5c) attStmt.x5c = attStmt.x5c.map(decodeCertificate);
    if (attStmt?.sig) attStmt.sig = base64urlEncode(attStmt.sig);
    
    return {
      fmt: decoded.fmt,
      attStmt,
      authData: decodeAuthenticatorData(decoded.authData)
    };
  } catch (error) {
    return { error: error.toString() };
  }
}

// Replace binary fields with base64url strings for logging
// Without this, binary fields (challenge, credential ids, etc.) serialize to empty objects
// The key parameter must be present for JSON.stringify() to call this replacer
function bufferReplacer(key, value) {
  if (value instanceof ArrayBuffer || ArrayBuffer.isView(value)) return base64urlEncode(value);
  return value;
}

// Turns a PublicKeyCredentialCreationOptions or PublicKeyCredentialRequestOptions into a loggable object, decoding its binary fields
function serializeOptions(options) {
  try {
    return JSON.parse(JSON.stringify(options.publicKey, bufferReplacer));
  } catch (error) {
    return { error: error.toString(), message: 'Failed to serialize options' };
  }
}

// Turns a PublicKeyCredential into a loggable object, decoding its binary fields
function serializeCredential(credential) {
  const json = credential.toJSON();
  const response = credential.response;

  json.response.clientDataJSON = JSON.parse(utf8Decoder.decode(new Uint8Array(response.clientDataJSON)));

  if (response.attestationObject) json.response.attestationObject = decodeAttestationObject(response.attestationObject);
  if (response.authenticatorData) json.response.authenticatorData = decodeAuthenticatorData(response.authenticatorData);

  return json;
}

// This will contain all callContentScript() promises still waiting on a reply, indexed by requestId
const pendingRequests = new Map();
// Counts up to give each request a unique id
let nextRequestId = 1;
// Add timeout to reject promises that don't get a reply in a reasonable time, so the RP doesn't hang forever
const REQUEST_TIMEOUT_MS = 5000;

// Listens for messages from content.js, which are either config updates or replies to callContentScript() requests
window.addEventListener('message', function (event) {
  // Ignore messages that are not from this window or don't have data
  if (event.source !== window || !event.data) return;

  const type = event.data.type;

  // Update the config when content.js pushes a new one, so the virtual authenticator uses the latest values
  if (type === 'WEBAUTHN_FLAG_CONFIG') {
    flagConfig = event.data.config;
    console.log(LOG_PREFIX, 'Flag config updated:', flagConfig);

  // Update the virtual authenticator enabled state when content.js pushes a new one
  } else if (type === 'WEBAUTHN_VIRTUAL_AUTHENTICATOR_ENABLED') {
    virtualAuthenticatorEnabled = event.data.config;
    console.log(LOG_PREFIX, 'Virtual authenticator enabled:', virtualAuthenticatorEnabled);

  // Handle replies from content.js to callContentScript() requests
  } else if (type === 'WEBAUTHN_VIRTUAL_RESPONSE') {
    const pending = pendingRequests.get(event.data.requestId);
    // In case somehow we get a reply for a request that has already timed out, ignore it
    if (!pending) return;

    pendingRequests.delete(event.data.requestId);

    if (event.data.success) pending.resolve(event.data.data);
    else pending.reject(new Error(event.data.error));
  }
});

// Asks content.js to run a chrome.storage operation and resolves with its result
function callContentScript(message) {
  const requestId = nextRequestId++;
  message.requestId = requestId;

  return new Promise(function (resolve, reject) {
    pendingRequests.set(requestId, { resolve, reject });
    window.postMessage(message, '*');

    setTimeout(function () {
      pendingRequests.delete(requestId);
      reject(new Error('Virtual authenticator: storage request timed out'));
    }, REQUEST_TIMEOUT_MS);
  });
}

// Logs an event to content.js, which will store it in chrome.storage.local
function logEvent(type, data) {
  window.postMessage({ type: 'WEBAUTHN_EVENT', event: { timestamp: new Date().toISOString(), type, url: location.href, data } }, '*');
}

// Builds the authenticator data for a virtual authenticator ceremony
async function buildAuthenticatorData(rpId, signCount, operation, credentialId, cosePublicKey) {
  // The first 37 bytes contain rpIdHash, flags, and signCount
  const baseAuthData = new Uint8Array(37);
  baseAuthData.set(await sha256(rpId));
  baseAuthData[32] = buildFlagByte(operation, flagConfig);
  const baseAuthDataView = new DataView(baseAuthData.buffer);
  baseAuthDataView.setUint32(33, signCount, false);

  // If this is a get operation, the authenticator data ends here (no attested credential data)
  if (operation === 'get') return baseAuthData;

  // Attested credential data: 16 zero bytes of AAGUID, then the credential id length, then the credential id itself
  const attested = new Uint8Array(18 + credentialId.length);
  const attestedView = new DataView(attested.buffer);
  attestedView.setUint16(16, credentialId.length, false);
  attested.set(credentialId, 18);

  return concatBytes(baseAuthData, attested, cosePublicKey);
}

// Builds the clientDataJSON for a virtual authenticator ceremony
function buildClientDataJson(type, challenge, origin) {
  const clientData = {
    type,
    challenge: base64urlEncode(challenge),
    origin,
    crossOrigin: false
  };

  return utf8Encoder.encode(JSON.stringify(clientData));
}

// Builds a PublicKeyCredential for a virtual authenticator ceremony
function buildPublicKeyCredential(id, rawId, response) {
  const type = 'public-key';
  const authenticatorAttachment = null; // just use null for virtual authenticator, since it is not a real device

  return {
    id,
    rawId,
    type,
    authenticatorAttachment,
    response,

    // An RP could call getClientExtensionResults() to see if any extensions were used, but the virtual authenticator does not support any extensions, so always return an empty object
    getClientExtensionResults() { return {}; },

    // An RP could call toJSON(), so it needs to be implemented
    toJSON() {
      const json = { clientDataJSON: base64urlEncode(response.clientDataJSON) };

      if (response.attestationObject) {
        json.attestationObject = base64urlEncode(response.attestationObject);
        json.transports = response.getTransports();
        json.authenticatorData = base64urlEncode(response.getAuthenticatorData());
        json.publicKeyAlgorithm = response.getPublicKeyAlgorithm();
        json.publicKey = base64urlEncode(response.getPublicKey());
      }

      if (response.authenticatorData) json.authenticatorData = base64urlEncode(response.authenticatorData);
      if (response.signature) json.signature = base64urlEncode(response.signature);
      if (response.userHandle) json.userHandle = base64urlEncode(response.userHandle);

      return {
        id,
        rawId: base64urlEncode(rawId),
        response: json,
        authenticatorAttachment,
        clientExtensionResults: {},
        type
      };
    }
  };
}

// Creates a new credential with the virtual authenticator
async function virtualCreate(options) {
  // The PublicKeyCredentialCreationOptions sent by the RP
  const creationOptions = options.publicKey;

  // RPs can omit the rp.id field, must then use the hostname
  const rpId = creationOptions.rp.id || location.hostname;

  // Generate the key pair and export it in different formats for the authenticator data, storage, and RP response
  const keyPair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  const publicJwk = await crypto.subtle.exportKey('jwk', keyPair.publicKey); // Used to build the COSE_Key for the authenticator data
  const privateJwk = await crypto.subtle.exportKey('jwk', keyPair.privateKey); // Used to store the private key in chrome.storage.local
  const spki = await crypto.subtle.exportKey('spki', keyPair.publicKey); // Used to return the public key to the RP in PublicKeyCredential

  // Convert the public key to a COSE_Key for the authenticator data, and generate a random credential id
  const cosePublicKey = encodeCosePublicKey(base64urlDecode(publicJwk.x), base64urlDecode(publicJwk.y));
  const credentialId = crypto.getRandomValues(new Uint8Array(16));

  const authData = await buildAuthenticatorData(rpId, 0, 'create', credentialId, cosePublicKey);

  const attestationObject = cborEncode({ fmt: 'none', attStmt: {}, authData });
  const clientDataJSON = buildClientDataJson('webauthn.create', creationOptions.challenge, location.origin);
  const credentialIdB64 = base64urlEncode(credentialId);

  let userHandle = null;
  let userName = '';
  let userDisplayName = '';
  if (creationOptions.user.id) userHandle = base64urlEncode(creationOptions.user.id);
  if (creationOptions.user.name) userName = creationOptions.user.name;
  if (creationOptions.user.displayName) userDisplayName = creationOptions.user.displayName;

  // Store the new credential in chrome.storage.local
  await callContentScript({
    type: 'WEBAUTHN_VIRTUAL_STORE_CREDENTIAL',
    credential: {
      credentialId: credentialIdB64,
      rpId,
      userHandle,
      userName,
      userDisplayName,
      privateKeyJwk: privateJwk,
      signCount: 0,
      createdAt: Date.now()
    }
  });

  // Create the response member of the PublicKeyCredential, which contains the clientDataJSON and attestationObject
  // Also include the helper methods, since some RPs may call them (getTransports(), getAuthenticatorData(), getPublicKey(), getPublicKeyAlgorithm())
  const response = {
    clientDataJSON: clientDataJSON.buffer,
    attestationObject: attestationObject.slice().buffer, // need to slice() because cborEncode() returns a Uint8Array view of a larger buffer, and the RP expects a buffer of exactly the right length
    getTransports() { return ['internal']; },
    getAuthenticatorData() { return authData.buffer; },
    getPublicKey() { return spki; },
    getPublicKeyAlgorithm() { return ES256; }
  };

  return buildPublicKeyCredential(credentialIdB64, credentialId.buffer, response);
}

// Gets a credential from the virtual authenticator, signs the assertion, and returns it to the RP
async function virtualGet(options) {
  // The PublicKeyCredentialRequestOptions sent by the RP
  const requestOptions = options.publicKey;

  // RPs can omit the rpId field, must then use the hostname
  const rpId = requestOptions.rpId || location.hostname;

  // The RP can specify a list of allowed credentials, which the virtual authenticator will filter against
  const allowCredentials = [];
  if (requestOptions.allowCredentials) {
    for (const descriptor of requestOptions.allowCredentials) {
      allowCredentials.push(base64urlEncode(descriptor.id));
    }
  }

  // Get the matching credentials from chrome.storage.local, and throw an error if none are found
  const credentials = await callContentScript({ type: 'WEBAUTHN_VIRTUAL_GET_CREDENTIALS', rpId, allowCredentials });
  if (credentials.length === 0) throw new DOMException('No virtual credentials available for this relying party', 'NotAllowedError');

  const stored = credentials[0]; // if multiple credentials match, just use the first one
  const credentialId = base64urlDecode(stored.credentialId);
  const privateKey = await crypto.subtle.importKey('jwk', stored.privateKeyJwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);

  const signCount = stored.signCount + 1;
  const authData = await buildAuthenticatorData(rpId, signCount, 'get');
  const clientDataJSON = buildClientDataJson('webauthn.get', requestOptions.challenge, location.origin);

  // Sign authenticatorData || SHA-256(clientDataJSON)
  const signedData = concatBytes(authData, await sha256(clientDataJSON));
  const signed = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, privateKey, signedData);

  // Web Crypto only produces raw P1363 (r || s), but WebAuthn assertions need DER
  const rawSignature = new Uint8Array(signed);
  const derHex = KJUR.crypto.ECDSA.concatSigToASN1Sig(rawSignature.toHex());
  const signature = Uint8Array.fromHex(derHex);

  // Update the signCount in chrome.storage.local
  await callContentScript({ type: 'WEBAUTHN_VIRTUAL_UPDATE_SIGCOUNT', credentialId: stored.credentialId, signCount });

  let userHandle = null;
  if (stored.userHandle) userHandle = base64urlDecode(stored.userHandle).buffer;

  // Create the response member of the PublicKeyCredential, which contains the clientDataJSON, authenticatorData, signature, and the userHandle
  const response = {
    clientDataJSON: clientDataJSON.buffer,
    authenticatorData: authData.buffer,
    signature: signature.buffer,
    userHandle
  };

  return buildPublicKeyCredential(stored.credentialId, credentialId.buffer, response);
}

// Logs a PublicKeyCredential to content.js
function logCredential(credential, isVirtual) {
  try {
    const serializedCredential = serializeCredential(credential);
    if (isVirtual) serializedCredential._virtual = true;
    logEvent('PublicKeyCredential (Client -> Server)', { credential: serializedCredential });
  } catch (logError) {
    console.error(LOG_PREFIX, 'Failed to log response:', logError);
    logEvent('PublicKeyCredential (Client -> Server)', { credential: null, logError: logError.toString() });
  }
}

// This actually intercepts navigator.credentials.create() and navigator.credentials.get(), logs the request, and either calls the virtual authenticator or the original method
function interceptCredentialsMethod(operation, requestLabel) {
  const original = navigator.credentials[operation];

  navigator.credentials[operation] = async function (options) {
    // Only intercept WebAuthn requests, which have a publicKey field. Other credential types (like passwords) are passed through to the original method without logging, since they are not relevant to this extension
    if (!options.publicKey) return original.call(this, options);

    logEvent(requestLabel, { options: serializeOptions(options) });

    try {
      const useVirtual = virtualAuthenticatorEnabled;

      let credential;
      if (useVirtual && operation === 'create') credential = await virtualCreate(options);
      else if (useVirtual) credential = await virtualGet(options);
      else credential = await original.call(this, options);

      logCredential(credential, useVirtual);
      return credential;

    } catch (error) {
      logEvent(operation + '_error', { name: error.name, message: error.message });
      throw error;
    }
  };
}

console.log(LOG_PREFIX, 'Wrapping navigator.credentials');
interceptCredentialsMethod('create', 'PublicKeyCredentialCreationOptions (Server -> Client)');
interceptCredentialsMethod('get', 'PublicKeyCredentialRequestOptions (Server -> Client)');
console.log(LOG_PREFIX, 'Initialized');

// Tell content.js that injected.js is ready to receive config updates and log events
window.postMessage({ type: 'WEBAUTHN_EXPLORER_READY' }, '*');