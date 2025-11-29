/**
 * SecureComm Cryptography Library
 * 
 * Full implementation with:
 * - ECDSA P-256 for digital signatures
 * - ECDH P-256 for key agreement
 * - AES-256-GCM for encryption
 * - HKDF for key derivation
 * - PBKDF2 for password-based key derivation
 */

// ==========================================
// UTILITY FUNCTIONS
// ==========================================

export const toBase64 = (buffer) => {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
};

export const fromBase64 = (str) => {
  const binary = atob(str);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
};

export const generateRandomBytes = (length) => {
  return crypto.getRandomValues(new Uint8Array(length));
};

// Clean JWK for cross-browser compatibility
export const cleanJwk = (jwk) => {
  const cleaned = { ...jwk };
  delete cleaned.key_ops;
  delete cleaned.ext;
  return cleaned;
};

// Clean JWK and remove private key component
export const cleanJwkPublic = (jwk) => {
  const cleaned = cleanJwk(jwk);
  delete cleaned.d;
  return cleaned;
};

// ==========================================
// KEY GENERATION
// ==========================================

export const generateSigningKeyPair = async () => {
  return crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign', 'verify']
  );
};

export const generateKeyAgreementKeyPair = async () => {
  return crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    ['deriveKey', 'deriveBits']
  );
};

export const generateUserKeys = async () => {
  const signingKp = await generateSigningKeyPair();
  const keyAgreementKp = await generateKeyAgreementKeyPair();
  
  // Export public keys
  const sigPubJwk = cleanJwkPublic(await crypto.subtle.exportKey('jwk', signingKp.publicKey));
  const kaePubJwk = cleanJwkPublic(await crypto.subtle.exportKey('jwk', keyAgreementKp.publicKey));
  
  return {
    privateKeys: {
      signing: signingKp.privateKey,
      keyAgreement: keyAgreementKp.privateKey
    },
    publicKeys: {
      identityKey: {
        algorithm: 'ECDSA-P256',
        publicKey: JSON.stringify(sigPubJwk)
      },
      keyAgreementKey: {
        algorithm: 'ECDH-P256',
        publicKey: JSON.stringify(kaePubJwk)
      }
    }
  };
};

// ==========================================
// KEY STORAGE (localStorage - encrypted)
// ==========================================

export const storePrivateKeys = async (userId, privateKeys, password) => {
  console.log('[CRYPTO] storePrivateKeys called with userId:', userId);
  
  try {
    // Export keys to JWK
    const sigJwk = await crypto.subtle.exportKey('jwk', privateKeys.signing);
    const kaeJwk = await crypto.subtle.exportKey('jwk', privateKeys.keyAgreement);
    console.log('[CRYPTO] Keys exported to JWK');
    
    // Derive encryption key from password using PBKDF2
    const pwKey = await crypto.subtle.importKey(
      'raw',
      new TextEncoder().encode(password),
      'PBKDF2',
      false,
      ['deriveKey']
    );
    
    const salt = generateRandomBytes(16);
    const encKey = await crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' },
      pwKey,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
    console.log('[CRYPTO] Encryption key derived from password');
    
    // Encrypt the keys
    const iv = generateRandomBytes(12);
    const data = JSON.stringify({ signing: sigJwk, keyAgreement: kaeJwk });
    const encrypted = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      encKey,
      new TextEncoder().encode(data)
    );
    console.log('[CRYPTO] Keys encrypted');
    
    // Store in localStorage (persistent across sessions)
    const storeKey = String(userId);
    localStorage.setItem(`privateKeys_${storeKey}`, JSON.stringify({
      encrypted: toBase64(encrypted),
      iv: toBase64(iv),
      salt: toBase64(salt)
    }));
    
    // ALSO store in sessionStorage (for fast access in current session)
    sessionStorage.setItem(`privateKeys_${storeKey}`, JSON.stringify({
      encrypted: toBase64(encrypted),
      iv: toBase64(iv),
      salt: toBase64(salt)
    }));
    
    console.log('[CRYPTO] ✅ Keys stored in localStorage and sessionStorage');
  } catch (err) {
    console.error('[CRYPTO] ❌ storePrivateKeys error:', err.message);
    throw err;
  }
};

export const retrievePrivateKeys = async (userId, password) => {
  console.log('[CRYPTO] retrievePrivateKeys called with userId:', userId);
  
  try {
    const lookupKey = String(userId);
    
    // Try sessionStorage first (fastest), then localStorage
    let storedData = sessionStorage.getItem(`privateKeys_${lookupKey}`);
    if (!storedData) {
      console.log('[CRYPTO] Not in sessionStorage, checking localStorage...');
      storedData = localStorage.getItem(`privateKeys_${lookupKey}`);
    }
    
    if (!storedData) {
      console.error('[CRYPTO] ❌ Keys not found in localStorage or sessionStorage');
      throw new Error('Keys not found');
    }
    
    console.log('[CRYPTO] ✅ Keys found');
    const stored = JSON.parse(storedData);
    
    // Derive decryption key
    const pwKey = await crypto.subtle.importKey(
      'raw',
      new TextEncoder().encode(password),
      'PBKDF2',
      false,
      ['deriveKey']
    );
    
    const encKey = await crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt: fromBase64(stored.salt), iterations: 100000, hash: 'SHA-256' },
      pwKey,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
    console.log('[CRYPTO] Decryption key derived');
    
    // Decrypt
    const decrypted = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: fromBase64(stored.iv) },
      encKey,
      fromBase64(stored.encrypted)
    );
    
    console.log('[CRYPTO] ✅ Keys decrypted successfully');
    
    const jwks = JSON.parse(new TextDecoder().decode(decrypted));
    
    // Import keys
    const signingKey = await crypto.subtle.importKey(
      'jwk',
      jwks.signing,
      { name: 'ECDSA', namedCurve: 'P-256' },
      true,
      ['sign']
    );
    
    const keyAgreementKey = await crypto.subtle.importKey(
      'jwk',
      jwks.keyAgreement,
      { name: 'ECDH', namedCurve: 'P-256' },
      true,
      ['deriveKey', 'deriveBits']
    );
    
    console.log('[CRYPTO] ✅ Keys imported successfully');
    
    return { signing: signingKey, keyAgreement: keyAgreementKey };
  } catch (err) {
    console.error('[CRYPTO] ❌ retrievePrivateKeys error:', err.message);
    throw err;
  }
};

// ==========================================
// SESSION KEY MANAGEMENT
// ==========================================

export const storeSessionKey = async (partnerId, sessionKey) => {
  const jwk = await crypto.subtle.exportKey('jwk', sessionKey);
  sessionStorage.setItem(`sessionKey_${partnerId}`, JSON.stringify(jwk));
};

export const retrieveSessionKey = async (partnerId) => {
  const data = sessionStorage.getItem(`sessionKey_${partnerId}`);
  if (!data) return null;
  
  const jwk = cleanJwk(JSON.parse(data));
  return crypto.subtle.importKey(
    'jwk',
    jwk,
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt']
  );
};

export const clearSessionKey = (partnerId) => {
  sessionStorage.removeItem(`sessionKey_${partnerId}`);
};

// ==========================================
// MESSAGE ENCRYPTION
// ==========================================

export const encryptMessage = async (sessionKey, plaintext) => {
  const iv = generateRandomBytes(12);
  const nonce = toBase64(generateRandomBytes(32));
  const timestamp = Date.now();
  
  const payload = JSON.stringify({ content: plaintext, timestamp, nonce });
  
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    sessionKey,
    new TextEncoder().encode(payload)
  );
  
  return {
    encryptedPayload: toBase64(ciphertext),
    iv: toBase64(iv),
    nonce,
    timestamp
  };
};

export const decryptMessage = async (sessionKey, encryptedData) => {
  const decrypted = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: fromBase64(encryptedData.iv) },
    sessionKey,
    fromBase64(encryptedData.encryptedPayload)
  );
  
  return JSON.parse(new TextDecoder().decode(decrypted));
};

// ==========================================
// KEY EXCHANGE PROTOCOL
// ==========================================

export const createKeyExchangeBundle = async (signingPrivateKey) => {
  // Generate ephemeral ECDH key pair
  const ephKp = await generateKeyAgreementKeyPair();
  
  // Get public key JWK
  const ephPubJwk = cleanJwkPublic(await crypto.subtle.exportKey('jwk', ephKp.publicKey));
  
  // Get signing public key for identity
  const sigPubJwk = cleanJwkPublic(await crypto.subtle.exportKey('jwk', signingPrivateKey));
  
  // Create bundle
  const timestamp = Date.now();
  const bundle = {
    ephemeralKey: JSON.stringify(ephPubJwk),
    identityKey: JSON.stringify(sigPubJwk),
    timestamp
  };
  
  // Sign the bundle
  const message = JSON.stringify(bundle);
  const signature = await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    signingPrivateKey,
    new TextEncoder().encode(message)
  );
  
  bundle.signature = toBase64(signature);
  
  return {
    bundle,
    ephemeralPrivateKey: ephKp.privateKey
  };
};

export const verifyAndDeriveKey = async (
  theirBundle,
  theirIdentityKey,
  myEphemeralPrivateKey,
  salt = null
) => {
  // Parse their ephemeral key
  const theirEphJwk = cleanJwk(JSON.parse(theirBundle.ephemeralKey));
  const theirIdJwk = cleanJwk(JSON.parse(theirBundle.identityKey));
  
  // Verify timestamp (5 minute window)
  if (Math.abs(Date.now() - theirBundle.timestamp) > 5 * 60 * 1000) {
    throw new Error('Timestamp expired - possible replay attack');
  }
  
  // Verify signature
  const messageToVerify = salt 
    ? JSON.stringify({
        ephemeralKey: theirBundle.ephemeralKey,
        identityKey: theirBundle.identityKey,
        salt: theirBundle.salt,
        timestamp: theirBundle.timestamp
      })
    : JSON.stringify({
        ephemeralKey: theirBundle.ephemeralKey,
        identityKey: theirBundle.identityKey,
        timestamp: theirBundle.timestamp
      });
  
  const valid = await crypto.subtle.verify(
    { name: 'ECDSA', hash: 'SHA-256' },
    theirIdentityKey,
    fromBase64(theirBundle.signature),
    new TextEncoder().encode(messageToVerify)
  );
  
  if (!valid) {
    throw new Error('Invalid signature - possible MITM attack');
  }
  
  // Import their ephemeral key
  const theirEphKey = await crypto.subtle.importKey(
    'jwk',
    theirEphJwk,
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    []
  );
  
  // Derive shared secret
  const sharedSecret = await crypto.subtle.deriveBits(
    { name: 'ECDH', public: theirEphKey },
    myEphemeralPrivateKey,
    256
  );
  
  // Use provided salt or generate new one
  const keySalt = salt ? fromBase64(salt) : generateRandomBytes(32);
  
  // Derive session key using HKDF
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    sharedSecret,
    'HKDF',
    false,
    ['deriveKey']
  );
  
  const sessionKey = await crypto.subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: keySalt,
      info: new TextEncoder().encode('SecureComm-E2EE-v1')
    },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt']
  );
  
  return {
    sessionKey,
    salt: toBase64(keySalt)
  };
};

export const createResponseBundle = async (signingPrivateKey, ephemeralPrivateKey, salt) => {
  // Export ephemeral public key
  const ephKp = await generateKeyAgreementKeyPair();
  const ephPubJwk = cleanJwkPublic(await crypto.subtle.exportKey('jwk', ephKp.publicKey));
  const sigPubJwk = cleanJwkPublic(await crypto.subtle.exportKey('jwk', signingPrivateKey));
  
  const timestamp = Date.now();
  const bundle = {
    ephemeralKey: JSON.stringify(ephPubJwk),
    identityKey: JSON.stringify(sigPubJwk),
    salt,
    timestamp
  };
  
  const message = JSON.stringify(bundle);
  const signature = await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    signingPrivateKey,
    new TextEncoder().encode(message)
  );
  
  bundle.signature = toBase64(signature);
  
  return {
    bundle,
    ephemeralPrivateKey: ephKp.privateKey
  };
};

// ==========================================
// FILE ENCRYPTION
// ==========================================

export const encryptFile = async (sessionKey, file) => {
  const buffer = await file.arrayBuffer();
  const data = new Uint8Array(buffer);
  
  // Hash for integrity
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hash = toBase64(hashBuffer);
  
  // Derive file key
  const salt = generateRandomBytes(32);
  const rawKey = await crypto.subtle.exportKey('raw', sessionKey);
  const keyMaterial = await crypto.subtle.importKey('raw', rawKey, 'HKDF', false, ['deriveKey']);
  const fileKey = await crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt, info: new TextEncoder().encode('file') },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt']
  );
  
  // Encrypt metadata
  const metaIv = generateRandomBytes(12);
  const metadata = JSON.stringify({
    fileName: file.name,
    mimeType: file.type,
    size: file.size,
    hash
  });
  const encryptedMeta = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: metaIv },
    fileKey,
    new TextEncoder().encode(metadata)
  );
  
  // Encrypt file data
  const dataIv = generateRandomBytes(12);
  const encryptedData = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: dataIv },
    fileKey,
    data
  );
  
  return {
    encryptedMetadata: { data: toBase64(encryptedMeta), iv: toBase64(metaIv) },
    encryptedData: { data: toBase64(encryptedData), iv: toBase64(dataIv) },
    encryption: { algorithm: 'AES-256-GCM', salt: toBase64(salt) },
    originalSize: file.size,
    hash
  };
};

export const decryptFile = async (sessionKey, encryptedFile) => {
  // Derive file key
  const salt = fromBase64(encryptedFile.encryption.salt);
  const rawKey = await crypto.subtle.exportKey('raw', sessionKey);
  const keyMaterial = await crypto.subtle.importKey('raw', rawKey, 'HKDF', false, ['deriveKey']);
  const fileKey = await crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt, info: new TextEncoder().encode('file') },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt']
  );
  
  // Decrypt metadata
  const metaBuffer = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: fromBase64(encryptedFile.encryptedMetadata.iv) },
    fileKey,
    fromBase64(encryptedFile.encryptedMetadata.data)
  );
  const metadata = JSON.parse(new TextDecoder().decode(metaBuffer));
  
  // Decrypt data
  const dataBuffer = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: fromBase64(encryptedFile.encryptedData.iv) },
    fileKey,
    fromBase64(encryptedFile.encryptedData.data)
  );
  
  // Verify hash
  const hashBuffer = await crypto.subtle.digest('SHA-256', dataBuffer);
  if (toBase64(hashBuffer) !== metadata.hash) {
    throw new Error('File integrity check failed');
  }
  
  return {
    data: new Blob([dataBuffer], { type: metadata.mimeType }),
    fileName: metadata.fileName,
    mimeType: metadata.mimeType
  };
};

// ==========================================
// DEBUGGING HELPERS
// ==========================================

export const debugSessionStorage = () => {
  console.log('[CRYPTO] 🔍 Storage Contents:');
  console.log('--- sessionStorage ---');
  for (let i = 0; i < sessionStorage.length; i++) {
    const key = sessionStorage.key(i);
    if (key.startsWith('privateKeys_')) {
      console.log(`  ${key}: stored`);
    }
  }
  console.log('--- localStorage ---');
  for (let i = 0; i < localStorage.length; i++) {
    const key = localStorage.key(i);
    if (key.startsWith('privateKeys_')) {
      console.log(`  ${key}: stored`);
    }
  }
};

export const debugCheckUser = async (userId) => {
  const userIdStr = String(userId);
  const sessionItem = sessionStorage.getItem(`privateKeys_${userIdStr}`);
  const localItem = localStorage.getItem(`privateKeys_${userIdStr}`);
  console.log(`[CRYPTO] 🔍 Check result for "${userIdStr}":`);
  console.log(`  sessionStorage: ${sessionItem ? 'FOUND' : 'NOT FOUND'}`);
  console.log(`  localStorage: ${localItem ? 'FOUND' : 'NOT FOUND'}`);
  return sessionItem || localItem;
};

// ==========================================
// EXPORT TO WINDOW
// ==========================================

window.CryptoLib = {
  toBase64,
  fromBase64,
  generateRandomBytes,
  cleanJwk,
  cleanJwkPublic,
  generateSigningKeyPair,
  generateKeyAgreementKeyPair,
  generateUserKeys,
  storePrivateKeys,
  retrievePrivateKeys,
  storeSessionKey,
  retrieveSessionKey,
  clearSessionKey,
  encryptMessage,
  decryptMessage,
  createKeyExchangeBundle,
  verifyAndDeriveKey,
  createResponseBundle,
  encryptFile,
  decryptFile,
  debugSessionStorage,
  debugCheckUser
};
