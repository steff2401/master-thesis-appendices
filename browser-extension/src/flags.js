// The position of each bit is defined in https://www.w3.org/TR/2026/CR-webauthn-3-20260113/#sctn-authenticator-data
const FLAG_BITS = {
  userPresent: 0x01,
  userVerified: 0x04,
  backupEligible: 0x08,
  backupState: 0x10,
  attestedCredentialData: 0x40,
  extensionData: 0x80
};

export const FLAG_LABELS = {
  userPresent: 'UP - User Present',
  userVerified: 'UV - User Verified',
  backupEligible: 'BE - Backup Eligible',
  backupState: 'BS - Backup State'
};

export const DEFAULT_FLAG_CONFIG = {
  create: {
    userPresent: true,
    userVerified: true,
    backupEligible: false,
    backupState: false
  },
  get: {
    userPresent: true,
    userVerified: true,
    backupEligible: false,
    backupState: false
  }
};

// Applies the flag values from the flagValues object to the given flagByte, returning the updated flag byte
function applyFlagValues(flagByte, flagValues) {
  let result = flagByte;

  for (const name in FLAG_LABELS) {
    const bit = FLAG_BITS[name];
    if (flagValues[name] === true) result |= bit;
    else if (flagValues[name] === false) result &= ~bit;
  }

  return result;
}

// Used in injected.js to set the flags in the virtual authenticator's authenticator data
export function buildFlagByte(operation, flagConfig) {
  // Start with the default flag values for the operation (create or get)
  let flagByte = applyFlagValues(0, DEFAULT_FLAG_CONFIG[operation]);

  // The attestedCredentialData bit is only set for create operations, not get operations
  if (operation === 'create') flagByte |= FLAG_BITS.attestedCredentialData;

  // Override the default flag values with any user-specified values from the flagConfig object
  if (flagConfig) flagByte = applyFlagValues(flagByte, flagConfig[operation]);

  return flagByte;
}

// Describes the values of the flags in flagByte in human-readable form, such as {userPresent: true, userVerified: false, etc.}
export function describeFlags(flagByte) {
  const flags = {};

  for (const name in FLAG_BITS) {
    const bit = FLAG_BITS[name];
    if (flagByte & bit) flags[name] = true;
    else flags[name] = false;
  }

  return flags;
}