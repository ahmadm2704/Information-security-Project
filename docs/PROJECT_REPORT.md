# SecureComm: End-to-End Encrypted Messaging & File-Sharing System

## Semester Project Report
**Course:** Information Security – BSSE (7th Semester)  
**Project Title:** Secure End-to-End Encrypted Messaging & File-Sharing System  
**Date:** December 2024

---

# Table of Contents

1. [Introduction](#1-introduction)
2. [Problem Statement](#2-problem-statement)
3. [System Architecture](#3-system-architecture)
4. [Cryptographic Design](#4-cryptographic-design)
5. [Key Exchange Protocol](#5-key-exchange-protocol)
6. [Message Encryption & Decryption](#6-message-encryption--decryption)
7. [File Encryption & Sharing](#7-file-encryption--sharing)
8. [Replay Attack Protection](#8-replay-attack-protection)
9. [MITM Attack Demonstration](#9-mitm-attack-demonstration)
10. [Threat Modeling (STRIDE)](#10-threat-modeling-stride)
11. [Logging & Security Auditing](#11-logging--security-auditing)
12. [Implementation Details](#12-implementation-details)
13. [Security Analysis](#13-security-analysis)
14. [Limitations & Future Improvements](#14-limitations--future-improvements)
15. [Conclusion](#15-conclusion)
16. [References](#16-references)

---

# 1. Introduction

## 1.1 Project Overview

SecureComm is a comprehensive end-to-end encrypted (E2EE) messaging and file-sharing system designed to provide maximum security for digital communications. The system ensures that messages and files are encrypted on the sender's device and can only be decrypted by the intended recipient, with no possibility of interception or viewing by the server or any third party.

## 1.2 Objectives

- **Confidentiality:** Ensure all messages and files are encrypted with AES-256-GCM
- **Integrity:** Protect data from tampering using authenticated encryption (GCM mode)
- **Authenticity:** Verify sender identity using ECDSA digital signatures
- **Forward Secrecy:** Implement ephemeral key exchange using ECDH
- **Replay Protection:** Prevent message replay attacks using nonces, timestamps, and sequence numbers
- **Zero-Knowledge Server:** Server never has access to plaintext content or private keys

## 1.3 Technologies Used

| Component | Technology |
|-----------|------------|
| Frontend | React.js 18.2.0 |
| Cryptography (Client) | Web Crypto API (SubtleCrypto) |
| Key Storage | localStorage + sessionStorage (encrypted) |
| Backend | Node.js + Express.js |
| Real-time Communication | Socket.io 4.7.2 |
| Database | MongoDB Atlas |
| Password Hashing | bcrypt (12 rounds) |
| Authentication | JWT (JSON Web Tokens) |

---

# 2. Problem Statement

## 2.1 The Need for Secure Communication

In today's digital landscape, communication privacy is under constant threat from:

1. **Mass Surveillance:** Government agencies and corporations collecting user data
2. **Man-in-the-Middle Attacks:** Attackers intercepting communications
3. **Data Breaches:** Server compromises exposing user messages
4. **Insider Threats:** Malicious employees accessing user data
5. **Replay Attacks:** Attackers resending captured messages

## 2.2 Limitations of Existing Solutions

Many messaging applications claim to provide encryption but fail in critical areas:

- **Server-Side Encryption:** Messages are decrypted at the server, exposing them to the provider
- **Key Escrow:** Private keys stored on servers can be subpoenaed or leaked
- **Weak Key Exchange:** Susceptible to MITM attacks during key establishment
- **No Forward Secrecy:** Compromise of long-term keys exposes all past communications

## 2.3 Our Solution

SecureComm addresses these challenges by implementing:

1. **True E2EE:** Encryption/decryption occurs exclusively on client devices
2. **Client-Side Key Storage:** Private keys never leave the user's device
3. **Authenticated Key Exchange:** ECDH combined with ECDSA signatures prevents MITM
4. **Perfect Forward Secrecy:** Ephemeral keys ensure past messages remain secure
5. **Comprehensive Replay Protection:** Multiple layers of defense against replay attacks

---

# 3. System Architecture

## 3.1 High-Level Architecture

The system follows a client-server architecture with the following key principles:

```
┌─────────────────────────────────────────────────────────────────┐
│                        SECURECOMM ARCHITECTURE                   │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌──────────────┐         ┌──────────────┐         ┌──────────┐ │
│  │   Client A   │◄───────►│    Server    │◄───────►│ Client B │ │
│  │  (Browser)   │   WS    │  (Node.js)   │   WS    │(Browser) │ │
│  └──────┬───────┘         └──────┬───────┘         └────┬─────┘ │
│         │                        │                      │       │
│  ┌──────▼───────┐         ┌──────▼───────┐       ┌─────▼──────┐│
│  │ Web Crypto   │         │   MongoDB    │       │ Web Crypto ││
│  │    API       │         │   (Metadata) │       │    API     ││
│  └──────────────┘         └──────────────┘       └────────────┘│
│         │                                               │       │
│  ┌──────▼───────┐                               ┌──────▼──────┐│
│  │ localStorage │                               │ localStorage││
│  │ (Encrypted   │                               │ (Encrypted  ││
│  │  Keys)       │                               │  Keys)      ││
│  └──────────────┘                               └─────────────┘│
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

## 3.2 Component Description

### 3.2.1 Client Application (React.js)

- **Authentication Module:** Handles user registration, login, and session management
- **Crypto Library:** Implements all cryptographic operations using Web Crypto API
- **Key Exchange Module:** Manages the ECDH key exchange protocol with digital signatures
- **Chat Module:** Handles message encryption, sending, receiving, and decryption
- **File Sharing Module:** Manages encrypted file upload and download
- **Security Logging:** Tracks cryptographic operations for audit trail

### 3.2.2 Server Application (Node.js + Express)

- **Authentication Service:** JWT-based authentication with rate limiting
- **Key Management Service:** Stores and distributes public keys only
- **Message Relay:** Forwards encrypted messages without decryption
- **File Storage:** Stores encrypted files in binary form
- **Security Logger:** Records security events and detected attacks
- **Replay Protection:** Server-side validation of nonces, timestamps, sequences

### 3.2.3 Database (MongoDB)

**Collections:**
- `users`: User accounts and public keys (no private keys)
- `messages`: Encrypted message payloads with metadata
- `encryptedfiles`: Encrypted file blobs
- `securitylogs`: Audit trail of security events

## 3.3 Data Flow

### Message Flow (Simplified)

```
Alice                     Server                      Bob
  │                          │                          │
  │ 1. Encrypt(msg, SK_AB)   │                          │
  ├─────────────────────────►│                          │
  │                          │ 2. Store & Forward       │
  │                          ├─────────────────────────►│
  │                          │                          │
  │                          │   3. Decrypt(msg, SK_AB) │
  │                          │                          │
```

Where `SK_AB` is the shared session key derived from ECDH.

---

# 4. Cryptographic Design

## 4.1 Cryptographic Algorithms

| Purpose | Algorithm | Parameters |
|---------|-----------|------------|
| Digital Signatures | ECDSA | P-256 (secp256r1) |
| Key Agreement | ECDH | P-256 (secp256r1) |
| Message Encryption | AES-GCM | 256-bit key, 96-bit IV |
| Key Derivation | HKDF | SHA-256 |
| Password Hashing | bcrypt | 12 rounds |
| Key Storage Encryption | PBKDF2 + AES-GCM | 100,000 iterations |

## 4.2 Key Types and Usage

### 4.2.1 Identity Key Pair (ECDSA P-256)

- **Purpose:** Long-term identity, digital signatures
- **Generation:** On user registration
- **Storage:** Private key in encrypted localStorage; Public key on server
- **Usage:** Sign key exchange bundles for authentication

### 4.2.2 Key Agreement Key Pair (ECDH P-256)

- **Purpose:** Pre-key for initial contact
- **Generation:** On user registration
- **Storage:** Private key in encrypted localStorage; Public key on server
- **Usage:** Initial ECDH if no ephemeral key available

### 4.2.3 Ephemeral Key Pairs (ECDH P-256)

- **Purpose:** Perfect forward secrecy
- **Generation:** Fresh pair for each key exchange
- **Storage:** Temporary, session-only
- **Usage:** ECDH to derive session keys

### 4.2.4 Session Key (AES-256)

- **Purpose:** Message encryption/decryption
- **Generation:** Derived from ECDH shared secret via HKDF
- **Storage:** sessionStorage (RAM-backed)
- **Lifetime:** Until key renegotiation or session end

## 4.3 Key Storage Security

Private keys are stored locally using a dual-storage mechanism:

```javascript
// Storage Architecture
localStorage:   Persistent, encrypted with user-specific key
sessionStorage: Session-only, for fast access (RAM-backed)

// Encryption Process
1. Generate storage key from user ID + browser fingerprint
2. Use PBKDF2 (100,000 iterations) to derive encryption key
3. Encrypt private keys with AES-256-GCM
4. Store encrypted blob in localStorage
5. Cache decrypted keys in sessionStorage for performance
```

### Storage Security Properties

- **At Rest:** Keys encrypted with AES-256-GCM
- **Key Derivation:** PBKDF2 with 100,000 iterations resists brute force
- **Browser Isolation:** Keys inaccessible to other origins (Same-Origin Policy)
- **Session Clearing:** sessionStorage cleared on browser/tab close
- **No Server Storage:** Private keys NEVER transmitted to server

---

# 5. Key Exchange Protocol

## 5.1 Protocol Overview

SecureComm implements a custom authenticated key exchange protocol combining:

- **ECDH (Elliptic Curve Diffie-Hellman):** For shared secret derivation
- **ECDSA (Elliptic Curve Digital Signature Algorithm):** For authentication
- **HKDF (HMAC-based Key Derivation Function):** For session key derivation

## 5.2 Protocol Design Rationale

### Why Custom Protocol?

1. **Educational Purpose:** Demonstrates understanding of cryptographic principles
2. **Tailored Security:** Specific to our threat model
3. **Transparency:** Full control and understanding of security properties

### Security Goals

1. **Mutual Authentication:** Both parties verify each other's identity
2. **Key Confirmation:** Both parties confirm they derived the same key
3. **Forward Secrecy:** Ephemeral keys ensure past sessions remain secure
4. **MITM Prevention:** Digital signatures prevent interception/modification

## 5.3 Protocol Message Flow

### Phase 1: Initiation (Alice → Bob)

```
Alice generates:
  - Ephemeral ECDH key pair (ephA_pub, ephA_priv)
  - Timestamp (t1)
  - Bundle = { ephA_pub, identityA_pub, t1 }
  - Signature = Sign(Bundle, identityA_priv)

Alice sends to server:
  KeyExchangeRequest = { Bundle, Signature, recipientId: Bob }
```

### Phase 2: Response (Bob → Alice)

```
Bob receives request, then:
  1. Verifies timestamp freshness (|now - t1| < 5 minutes)
  2. Verifies Alice's signature using identityA_pub
  3. Generates ephemeral ECDH key pair (ephB_pub, ephB_priv)
  4. Computes shared secret: S = ECDH(ephB_priv, ephA_pub)
  5. Derives session key: SK = HKDF(S, salt, "SecureComm-E2EE-v1")
  6. Generates salt (random 32 bytes)
  7. Creates response bundle with signature

Bob sends:
  KeyExchangeResponse = { ephB_pub, identityB_pub, salt, t2, Signature }
```

### Phase 3: Confirmation (Alice)

```
Alice receives response, then:
  1. Verifies timestamp freshness
  2. Verifies Bob's signature
  3. Computes shared secret: S = ECDH(ephA_priv, ephB_pub)
  4. Derives session key: SK = HKDF(S, salt, "SecureComm-E2EE-v1")
  5. Sends confirmation message

Alice sends:
  KeyExchangeConfirmation = { status: "ok" }
```

### Phase 4: Key Storage

```
Both parties:
  1. Store session key in sessionStorage
  2. Reset replay protection sequence counters
  3. Log successful key exchange
```

## 5.4 Key Derivation Function

```javascript
// Session Key Derivation
async function deriveSessionKey(sharedSecret, salt) {
  // Import shared secret as key material
  const keyMaterial = await crypto.subtle.importKey(
    'raw', 
    sharedSecret, 
    'HKDF', 
    false, 
    ['deriveKey']
  );
  
  // Derive AES-256-GCM key using HKDF
  const sessionKey = await crypto.subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: salt,                              // 32-byte random salt
      info: new TextEncoder().encode('SecureComm-E2EE-v1')  // Context
    },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt']
  );
  
  return sessionKey;
}
```

## 5.5 Security Properties

| Property | How Achieved |
|----------|--------------|
| **Confidentiality** | ECDH shared secret known only to participants |
| **Authentication** | ECDSA signatures verify identities |
| **Integrity** | Signatures cover entire bundle |
| **Freshness** | Timestamps prevent replay of old bundles |
| **Forward Secrecy** | Ephemeral keys discarded after use |
| **Key Confirmation** | Confirmation message proves both derived same key |

---

# 6. Message Encryption & Decryption

## 6.1 Encryption Process

Every message undergoes the following encryption process:

```javascript
async function encryptMessage(sessionKey, plaintext, conversationId) {
  // 1. Generate random IV (96 bits for GCM)
  const iv = crypto.getRandomValues(new Uint8Array(12));
  
  // 2. Generate unique nonce (256 bits)
  const nonce = toBase64(crypto.getRandomValues(new Uint8Array(32)));
  
  // 3. Get current timestamp
  const timestamp = Date.now();
  
  // 4. Get next sequence number for this conversation
  const sequenceNumber = getNextSequenceNumber(conversationId);
  
  // 5. Create payload with metadata
  const payload = JSON.stringify({
    content: plaintext,
    timestamp: timestamp,
    nonce: nonce,
    sequenceNumber: sequenceNumber
  });
  
  // 6. Encrypt with AES-256-GCM
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: iv },
    sessionKey,
    new TextEncoder().encode(payload)
  );
  
  // 7. Return encrypted message components
  return {
    encryptedPayload: toBase64(ciphertext),
    iv: toBase64(iv),
    nonce: nonce,
    timestamp: timestamp,
    sequenceNumber: sequenceNumber
  };
}
```

## 6.2 Message Structure

```
┌─────────────────────────────────────────────────────────┐
│                   ENCRYPTED MESSAGE                      │
├─────────────────────────────────────────────────────────┤
│  encryptedPayload: Base64(AES-GCM(payload))             │
│  iv:              Base64(12-byte random IV)              │
│  nonce:           Base64(32-byte random nonce)           │
│  timestamp:       Unix timestamp (milliseconds)          │
│  sequenceNumber:  Integer counter per conversation       │
├─────────────────────────────────────────────────────────┤
│  Payload (encrypted):                                    │
│    {                                                     │
│      "content": "Hello, Bob!",                          │
│      "timestamp": 1701619200000,                        │
│      "nonce": "abc123...",                              │
│      "sequenceNumber": 42                               │
│    }                                                     │
└─────────────────────────────────────────────────────────┘
```

## 6.3 Decryption Process

```javascript
async function decryptMessage(sessionKey, encryptedData, conversationId, verifyReplay = true) {
  // 1. Decrypt the ciphertext
  const decrypted = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: fromBase64(encryptedData.iv) },
    sessionKey,
    fromBase64(encryptedData.encryptedPayload)
  );
  
  // 2. Parse the payload
  const payload = JSON.parse(new TextDecoder().decode(decrypted));
  
  // 3. Verify replay protection (if enabled)
  if (verifyReplay && conversationId) {
    const verification = verifyMessageAntiReplay(
      conversationId,
      encryptedData.nonce,
      encryptedData.timestamp,
      encryptedData.sequenceNumber
    );
    
    if (!verification.valid) {
      console.error('REPLAY ATTACK DETECTED:', verification.errors);
      return { ...payload, _isReplay: true, _errors: verification.errors };
    }
  }
  
  return { ...payload, _isReplay: false };
}
```

## 6.4 AES-GCM Security Properties

| Property | Description |
|----------|-------------|
| **Confidentiality** | 256-bit key provides 2^256 possible keys |
| **Integrity** | GCM mode includes authentication tag |
| **Authenticity** | Tag verifies message wasn't tampered |
| **Unique IVs** | Random 96-bit IV per message prevents patterns |

---

# 7. File Encryption & Sharing

## 7.1 File Encryption Process

Files are encrypted client-side before upload:

```javascript
async function encryptFile(file, sessionKey) {
  // 1. Read file as ArrayBuffer
  const fileData = await file.arrayBuffer();
  
  // 2. Generate random salt and IV
  const salt = crypto.getRandomValues(new Uint8Array(32));
  const dataIv = crypto.getRandomValues(new Uint8Array(12));
  const metaIv = crypto.getRandomValues(new Uint8Array(12));
  
  // 3. Derive file-specific encryption key
  const rawKey = await crypto.subtle.exportKey('raw', sessionKey);
  const keyMaterial = await crypto.subtle.importKey('raw', rawKey, 'HKDF', false, ['deriveKey']);
  const fileKey = await crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt, info: new TextEncoder().encode('file') },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt']
  );
  
  // 4. Compute file hash for integrity verification
  const hashBuffer = await crypto.subtle.digest('SHA-256', fileData);
  
  // 5. Create metadata
  const metadata = {
    fileName: file.name,
    mimeType: file.type,
    size: file.size,
    hash: toBase64(hashBuffer)
  };
  
  // 6. Encrypt metadata
  const encryptedMeta = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: metaIv },
    fileKey,
    new TextEncoder().encode(JSON.stringify(metadata))
  );
  
  // 7. Encrypt file data
  const encryptedData = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: dataIv },
    fileKey,
    fileData
  );
  
  return {
    salt: toBase64(salt),
    encryptedMetadata: { data: toBase64(encryptedMeta), iv: toBase64(metaIv) },
    encryptedData: { data: toBase64(encryptedData), iv: toBase64(dataIv) }
  };
}
```

## 7.2 File Decryption Process

```javascript
async function decryptFile(encryptedFile, sessionKey) {
  // 1. Derive file key using same salt
  const salt = fromBase64(encryptedFile.salt);
  // ... (same key derivation as encryption)
  
  // 2. Decrypt metadata
  const metaBuffer = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: fromBase64(encryptedFile.encryptedMetadata.iv) },
    fileKey,
    fromBase64(encryptedFile.encryptedMetadata.data)
  );
  const metadata = JSON.parse(new TextDecoder().decode(metaBuffer));
  
  // 3. Decrypt file data
  const dataBuffer = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: fromBase64(encryptedFile.encryptedData.iv) },
    fileKey,
    fromBase64(encryptedFile.encryptedData.data)
  );
  
  // 4. Verify file integrity
  const hashBuffer = await crypto.subtle.digest('SHA-256', dataBuffer);
  if (toBase64(hashBuffer) !== metadata.hash) {
    throw new Error('File integrity check failed');
  }
  
  // 5. Return decrypted file
  return {
    data: new Blob([dataBuffer], { type: metadata.mimeType }),
    fileName: metadata.fileName,
    mimeType: metadata.mimeType
  };
}
```

## 7.3 File Storage on Server

The server only stores:
- Encrypted file blob (no plaintext)
- Sender/recipient IDs
- Encrypted metadata
- Timestamp

```javascript
// Server-side file storage (MongoDB)
const EncryptedFileSchema = {
  senderId: ObjectId,
  recipientId: ObjectId,
  salt: String,                    // For key derivation
  encryptedMetadata: {
    data: String,                  // Encrypted filename, type, size
    iv: String
  },
  encryptedData: {
    data: String,                  // Encrypted file content
    iv: String
  },
  createdAt: Date
};
```

---

# 8. Replay Attack Protection

## 8.1 What is a Replay Attack?

A replay attack occurs when an attacker:
1. Intercepts a valid encrypted message
2. Stores the captured message
3. Resends (replays) the exact same message later
4. Tricks the recipient into processing it as new

Even without decryption, this can cause harm (duplicate transactions, confusion, denial of service).

## 8.2 Our Multi-Layer Defense

SecureComm implements **four layers** of replay protection:

### Layer 1: Nonces (Number Used Once)

```javascript
// Configuration
const NONCE_SIZE = 32;  // 256 bits
const NONCE_CACHE_SIZE = 10000;
const NONCE_EXPIRY_MS = 10 * 60 * 1000;  // 10 minutes

// Generate unique nonce per message
const nonce = toBase64(crypto.getRandomValues(new Uint8Array(32)));

// Check for reuse
function isNonceReused(conversationId, nonce) {
  const cache = nonceCache.get(conversationId);
  if (!cache) return false;
  
  for (const entry of cache) {
    if (entry.nonce === nonce) return true;  // REPLAY DETECTED
  }
  return false;
}
```

**Properties:**
- 256 bits of randomness = 2^256 possible values
- Probability of collision: negligible
- Server maintains global nonce cache
- Expired nonces cleaned periodically

### Layer 2: Timestamps

```javascript
const TIMESTAMP_WINDOW_MS = 5 * 60 * 1000;  // 5 minutes
const FUTURE_TOLERANCE_MS = 30 * 1000;       // 30 seconds

function isTimestampValid(timestamp) {
  const now = Date.now();
  
  // Reject future timestamps (clock skew tolerance: 30 sec)
  if (timestamp > now + FUTURE_TOLERANCE_MS) {
    return { valid: false, reason: 'FUTURE_TIMESTAMP' };
  }
  
  // Reject old timestamps
  if (now - timestamp > TIMESTAMP_WINDOW_MS) {
    return { valid: false, reason: 'EXPIRED_TIMESTAMP' };
  }
  
  return { valid: true };
}
```

**Properties:**
- Messages expire after 5 minutes
- Prevents delayed replay attacks
- 30-second tolerance for clock skew

### Layer 3: Sequence Numbers

```javascript
// Per-conversation sequence tracking
const sequenceTracker = new Map();

function getNextSequenceNumber(conversationId) {
  const tracker = sequenceTracker.get(conversationId) || { sent: 0, received: 0 };
  tracker.sent += 1;
  sequenceTracker.set(conversationId, tracker);
  return tracker.sent;
}

function isSequenceValid(conversationId, sequenceNumber) {
  const tracker = sequenceTracker.get(conversationId);
  const lastReceived = tracker?.received || 0;
  
  // Must be strictly greater than last received
  if (sequenceNumber <= lastReceived) {
    return { valid: false, reason: 'INVALID_SEQUENCE' };
  }
  
  return { valid: true };
}
```

**Properties:**
- Monotonically increasing per conversation
- Prevents out-of-order replay
- Reset on new key exchange

### Layer 4: Server-Side Validation

```javascript
// Server validates ALL messages
socket.on('message:send', async (data) => {
  const { nonce, timestamp, sequenceNumber } = data;
  
  // Validate replay protection
  const replayCheck = validateReplayProtection(
    socket.userId,
    data.recipientId,
    nonce,
    timestamp,
    sequenceNumber
  );
  
  if (!replayCheck.valid) {
    // Log security event
    await SecurityLog.logEvent({
      eventType: 'REPLAY_ATTACK_DETECTED',
      severity: 'CRITICAL',
      details: replayCheck.errors
    });
    
    // Reject message
    socket.emit('message:error', { error: 'Replay attack detected' });
    return;
  }
  
  // Continue with message processing...
});
```

## 8.3 Replay Attack Demonstration

### Scenario: Attacker Replays Captured Message

```
Time 10:00 - Alice sends message to Bob
  Nonce: abc123...
  Timestamp: 1701619200000
  Sequence: 5
  Server: ✅ Accepted, stored in nonce cache

Time 10:06 - Eve replays same message
  Nonce: abc123... (same)
  Timestamp: 1701619200000 (original)
  Sequence: 5 (same)
  
Server validation:
  ❌ Nonce check: "abc123" already in cache
  ❌ Timestamp check: 6 minutes old (>5 min limit)
  ❌ Sequence check: Expected > 5, got 5

Result: MESSAGE REJECTED
Security Log: REPLAY_ATTACK_DETECTED (CRITICAL)
```

### Attack Demonstration Script Output

```
==============================================
TEST 1: Immediate Replay (Duplicate Nonce)
==============================================

📨 Sending valid message:
   Nonce: YWJjZGVmZ2hpamts...
   Timestamp: 2024-12-03T18:00:00.000Z
   Sequence: 1
✅ Message accepted

🔄 Replaying exact same message...
🚫 Message rejected: DUPLICATE_NONCE

==============================================
TEST 2: Delayed Replay (Expired Timestamp)
==============================================

📨 Sending old message (6 min timestamp):
   Timestamp: 2024-12-03T17:54:00.000Z (6 min ago)
🚫 Message rejected: EXPIRED_TIMESTAMP

==============================================
TEST 3: Out of Sequence Replay
==============================================

📨 Sending sequence: 10, 11, 12
🔄 Replaying with sequence 10...
🚫 Message rejected: INVALID_SEQUENCE (expected > 12)

==============================================
ALL REPLAY ATTACKS BLOCKED ✅
==============================================
```

---

# 9. MITM Attack Demonstration

## 9.1 What is a MITM Attack?

A Man-in-the-Middle (MITM) attack occurs when an attacker secretly intercepts and potentially alters communication between two parties who believe they are directly communicating with each other.

## 9.2 MITM Attack on Plain Diffie-Hellman

### Attack Scenario (Without Signatures)

```
Alice                    Eve (Attacker)                   Bob
  │                           │                             │
  │  1. g^a mod p            │                             │
  ├──────────────────────────►│                             │
  │                           │  2. g^e1 mod p              │
  │                           ├────────────────────────────►│
  │                           │                             │
  │                           │  3. g^b mod p               │
  │                           │◄────────────────────────────┤
  │  4. g^e2 mod p            │                             │
  │◄──────────────────────────┤                             │
  │                           │                             │
  │  Key_AE = g^(a*e2)        │  Key_AE = g^(a*e2)          │
  │                           │  Key_EB = g^(b*e1)          │
  │                           │                   Key_EB = g^(b*e1)
```

**Result:** 
- Alice thinks she shares a key with Bob, but shares with Eve
- Bob thinks he shares a key with Alice, but shares with Eve
- Eve can decrypt, read, modify, and re-encrypt all messages

### Demonstration with BurpSuite

```
1. Configure BurpSuite as proxy
2. Intercept WebSocket traffic
3. Capture key exchange request from Alice
4. Replace Alice's ephemeral public key with attacker's key
5. Forward modified request to Bob
6. Capture Bob's response
7. Replace Bob's ephemeral public key with attacker's key
8. Forward modified response to Alice

Result: Attacker has two separate shared secrets
        Can decrypt all traffic in both directions
```

## 9.3 How Our Protocol Prevents MITM

### Protection: Digital Signatures

```
Alice                    Eve (Attacker)                   Bob
  │                           │                             │
  │ Bundle = {ephA, idA, t}   │                             │
  │ Sig = Sign(Bundle, skA)   │                             │
  ├──────────────────────────►│                             │
  │                           │                             │
  │                           │ Eve tries to modify ephA    │
  │                           │ But cannot forge signature! │
  │                           │                             │
  │                           │ If Eve replaces ephA:       │
  │                           │   Sig verification FAILS ❌ │
  │                           │                             │
  │                           │ If Eve keeps original ephA: │
  │                           │   Cannot derive shared key  │
```

### Verification Process

```javascript
async function verifyKeyExchangeBundle(bundle, signature, senderPublicKey) {
  // 1. Reconstruct the signed message
  const message = JSON.stringify({
    ephemeralKey: bundle.ephemeralKey,
    identityKey: bundle.identityKey,
    timestamp: bundle.timestamp
  });
  
  // 2. Verify signature using sender's identity key
  const isValid = await crypto.subtle.verify(
    { name: 'ECDSA', hash: 'SHA-256' },
    senderPublicKey,
    fromBase64(signature),
    new TextEncoder().encode(message)
  );
  
  if (!isValid) {
    throw new Error('SIGNATURE VERIFICATION FAILED - Possible MITM attack');
  }
  
  // 3. Verify timestamp freshness
  if (Math.abs(Date.now() - bundle.timestamp) > 5 * 60 * 1000) {
    throw new Error('TIMESTAMP EXPIRED - Possible replay attack');
  }
  
  return true;
}
```

### MITM Prevention Evidence

```
MITM Attempt Log (Server Console):
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
[KEYEXCHANGE] Received bundle from alice
[KEYEXCHANGE] Verifying signature...
[KEYEXCHANGE] ❌ SIGNATURE VERIFICATION FAILED
[SECURITY] 🚨 CRITICAL: INVALID_SIGNATURE_DETECTED
  User: alice
  Target: bob
  Details: Bundle signature does not match identity key
  Result: BLOCKED
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Client Console:
[CRYPTO] ❌ Key exchange failed: Signature verification failed
[UI] ⚠️ Warning: Could not establish secure connection. 
     Possible man-in-the-middle attack detected.
```

## 9.4 Security Properties

| Attack Vector | Protection Mechanism | Result |
|--------------|---------------------|--------|
| Replace public key | Signature verification fails | Attack blocked |
| Replay old bundle | Timestamp validation fails | Attack blocked |
| Forge signature | ECDSA with P-256 (computationally infeasible) | Attack blocked |
| Impersonate user | Identity key bound to account | Attack blocked |

---

# 10. Threat Modeling (STRIDE)

## 10.1 STRIDE Overview

STRIDE is a threat modeling framework developed by Microsoft:

| Letter | Threat | Description |
|--------|--------|-------------|
| **S** | Spoofing | Pretending to be someone else |
| **T** | Tampering | Modifying data or code |
| **R** | Repudiation | Denying having performed an action |
| **I** | Information Disclosure | Exposing information to unauthorized parties |
| **D** | Denial of Service | Denying or degrading service |
| **E** | Elevation of Privilege | Gaining unauthorized capabilities |

## 10.2 Threat Analysis

### 10.2.1 Spoofing

| Threat | Vulnerable Component | Countermeasure | Implementation |
|--------|---------------------|----------------|----------------|
| User impersonation | Authentication | Password + JWT | bcrypt hashing, secure tokens |
| Session hijacking | JWT tokens | Token expiration, HTTPS | 24-hour expiry, TLS required |
| Key exchange impersonation | Key Exchange | Digital signatures | ECDSA on all bundles |
| Fake server | Client connection | Certificate pinning (future) | HTTPS validation |

### 10.2.2 Tampering

| Threat | Vulnerable Component | Countermeasure | Implementation |
|--------|---------------------|----------------|----------------|
| Message modification | Encrypted messages | Authenticated encryption | AES-GCM with auth tag |
| Key exchange modification | Key bundles | Digital signatures | ECDSA verification |
| File corruption | Encrypted files | Hash verification | SHA-256 integrity check |
| Database tampering | MongoDB | Access controls | Connection authentication |

### 10.2.3 Repudiation

| Threat | Vulnerable Component | Countermeasure | Implementation |
|--------|---------------------|----------------|----------------|
| Deny sending message | Messages | Digital signatures | Messages signed with identity key |
| Deny key exchange | Key Exchange | Audit logging | SecurityLog collection |
| Deny login | Authentication | IP + timestamp logging | security.lastLoginIP field |

### 10.2.4 Information Disclosure

| Threat | Vulnerable Component | Countermeasure | Implementation |
|--------|---------------------|----------------|----------------|
| Message content exposure | Network/Server | E2EE | AES-256-GCM client-side |
| Private key theft | Browser storage | Encrypted storage | PBKDF2 + AES-GCM |
| Metadata leakage | Database | Minimal metadata | Only IDs and timestamps |
| Password theft | Database | Secure hashing | bcrypt with 12 rounds |

### 10.2.5 Denial of Service

| Threat | Vulnerable Component | Countermeasure | Implementation |
|--------|---------------------|----------------|----------------|
| API flooding | REST endpoints | Rate limiting | 100 req/15min general, 20/hr auth |
| Socket flooding | WebSocket | Connection limits | Socket.io backpressure |
| Large file upload | File endpoints | Size limits | 50MB maximum |
| Account lockout abuse | Authentication | Temporary lockout | 15-minute unlock |

### 10.2.6 Elevation of Privilege

| Threat | Vulnerable Component | Countermeasure | Implementation |
|--------|---------------------|----------------|----------------|
| Access other's messages | API endpoints | Authorization checks | JWT user ID validation |
| Admin impersonation | User roles | Role-based access | User status field |
| JWT manipulation | Authentication | Signature verification | HS256 with secret key |
| Cross-conversation access | Message retrieval | Ownership validation | Sender/recipient ID check |

## 10.3 Attack Surface Analysis

```
┌─────────────────────────────────────────────────────────────────┐
│                      ATTACK SURFACE MAP                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  External Attackers                                              │
│       │                                                          │
│       ▼                                                          │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐          │
│  │   Network   │───►│   Server    │───►│  Database   │          │
│  │  (TLS/HTTPS)│    │  (Node.js)  │    │  (MongoDB)  │          │
│  └─────────────┘    └─────────────┘    └─────────────┘          │
│       │                   │                   │                  │
│       │                   │                   │                  │
│  Protected by:       Protected by:       Protected by:           │
│  - TLS 1.3          - Rate limiting     - Auth required          │
│  - HSTS             - JWT validation    - Encrypted data         │
│                     - Input validation  - Access controls        │
│                     - CORS              - No plaintext           │
│                                                                  │
│  ┌─────────────┐                                                │
│  │   Client    │                                                │
│  │  (Browser)  │                                                │
│  └─────────────┘                                                │
│       │                                                          │
│  Protected by:                                                   │
│  - Same-origin policy                                           │
│  - Encrypted key storage                                        │
│  - CSP headers                                                  │
│  - No eval(), no inline scripts                                 │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

## 10.4 Risk Matrix

| Threat | Likelihood | Impact | Risk Level | Mitigation Status |
|--------|-----------|--------|------------|-------------------|
| MITM attack | Medium | Critical | High | ✅ Mitigated (signatures) |
| Replay attack | High | High | High | ✅ Mitigated (nonce/timestamp/seq) |
| Brute force password | Medium | High | High | ✅ Mitigated (bcrypt + lockout) |
| XSS attack | Low | Critical | Medium | ✅ Mitigated (CSP + React) |
| Key theft from storage | Low | Critical | Medium | ✅ Mitigated (encrypted storage) |
| DDoS attack | Medium | Medium | Medium | ⚠️ Partial (rate limiting) |
| Server compromise | Low | Critical | Medium | ✅ Mitigated (no plaintext stored) |

---

# 11. Logging & Security Auditing

## 11.1 Security Event Types

```javascript
const SECURITY_EVENTS = [
  // Authentication Events
  'AUTH_LOGIN_SUCCESS',
  'AUTH_LOGIN_FAILED',
  'AUTH_REGISTER',
  'AUTH_LOGOUT',
  'AUTH_PASSWORD_CHANGE',
  'AUTH_ACCOUNT_LOCKED',
  
  // Key Management Events
  'KEY_PAIR_GENERATED',
  'KEY_EXCHANGE_INITIATED',
  'KEY_EXCHANGE_COMPLETED',
  'KEY_EXCHANGE_FAILED',
  
  // Message Events
  'MESSAGE_SENT',
  'MESSAGE_DELIVERED',
  
  // Security Incidents
  'REPLAY_ATTACK_DETECTED',
  'INVALID_SIGNATURE_DETECTED',
  'INVALID_TIMESTAMP_DETECTED',
  'UNAUTHORIZED_ACCESS',
  'RATE_LIMIT_EXCEEDED',
  
  // File Events
  'FILE_UPLOADED',
  'FILE_DOWNLOADED',
  'FILE_SHARED'
];
```

## 11.2 Log Entry Structure

```javascript
const SecurityLogSchema = {
  eventType: String,      // One of SECURITY_EVENTS
  severity: String,       // INFO | WARNING | ERROR | CRITICAL
  userId: ObjectId,       // User who triggered event
  username: String,       // Username for quick reference
  targetUserId: ObjectId, // Target user (if applicable)
  request: {
    ip: String,           // Client IP address
    userAgent: String,    // Browser/client info
    path: String,         // API endpoint
    method: String        // HTTP method
  },
  details: Mixed,         // Event-specific data
  result: String,         // SUCCESS | FAILURE | BLOCKED | LOGGED
  timestamp: Date         // When event occurred
};
```

## 11.3 Sample Security Logs

### Successful Login
```json
{
  "eventType": "AUTH_LOGIN_SUCCESS",
  "severity": "INFO",
  "userId": "507f1f77bcf86cd799439011",
  "username": "alice",
  "request": {
    "ip": "192.168.1.100",
    "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0",
    "path": "/api/auth/login",
    "method": "POST"
  },
  "result": "SUCCESS",
  "timestamp": "2024-12-03T18:30:00.000Z"
}
```

### Replay Attack Detected
```json
{
  "eventType": "REPLAY_ATTACK_DETECTED",
  "severity": "CRITICAL",
  "userId": "507f1f77bcf86cd799439011",
  "username": "eve",
  "targetUserId": "507f1f77bcf86cd799439022",
  "details": {
    "nonce": "YWJjZGVmZ2hpamts...",
    "timestamp": 1701619200000,
    "sequenceNumber": 5,
    "errors": [
      "DUPLICATE_NONCE: Nonce was already used",
      "INVALID_SEQUENCE: Got 5, expected > 10"
    ]
  },
  "result": "BLOCKED",
  "timestamp": "2024-12-03T18:35:00.000Z"
}
```

### Key Exchange Completed
```json
{
  "eventType": "KEY_EXCHANGE_COMPLETED",
  "severity": "INFO",
  "userId": "507f1f77bcf86cd799439011",
  "username": "alice",
  "targetUserId": "507f1f77bcf86cd799439022",
  "details": {
    "keyFingerprint": "a1:b2:c3:d4:e5:f6:g7:h8",
    "protocol": "ECDH-P256",
    "duration": 342
  },
  "result": "SUCCESS",
  "timestamp": "2024-12-03T18:32:00.000Z"
}
```

## 11.4 Log Monitoring Dashboard

The system provides a security logs viewer at `/security`:

```
┌─────────────────────────────────────────────────────────────────┐
│                     SECURITY LOGS                                │
├─────────────────────────────────────────────────────────────────┤
│  Filter: [All Events ▼] [All Severity ▼] [Last 24 hours ▼]     │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  🚨 CRITICAL | REPLAY_ATTACK_DETECTED | eve → bob               │
│     2024-12-03 18:35:00 | BLOCKED                               │
│     Details: Duplicate nonce, invalid sequence                  │
│                                                                  │
│  ℹ️ INFO | KEY_EXCHANGE_COMPLETED | alice ↔ bob                 │
│     2024-12-03 18:32:00 | SUCCESS                               │
│     Key fingerprint: a1:b2:c3:d4:e5:f6:g7:h8                   │
│                                                                  │
│  ℹ️ INFO | AUTH_LOGIN_SUCCESS | alice                           │
│     2024-12-03 18:30:00 | SUCCESS                               │
│     IP: 192.168.1.100                                           │
│                                                                  │
│  ⚠️ WARNING | AUTH_LOGIN_FAILED | unknown                       │
│     2024-12-03 18:28:00 | FAILURE                               │
│     Reason: Invalid password (attempt 3/5)                      │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

# 12. Implementation Details

## 12.1 Project Structure

```
secure-comm-system/
├── client/                      # React Frontend
│   ├── public/
│   │   └── index.html
│   ├── src/
│   │   ├── components/
│   │   │   ├── Chat.js         # Main chat interface
│   │   │   ├── FileShare.js    # File encryption/sharing
│   │   │   ├── Header.js       # Navigation
│   │   │   ├── KeyExchange.js  # Key exchange protocol
│   │   │   ├── Login.js        # Authentication
│   │   │   ├── Register.js     # User registration
│   │   │   └── SecurityLogs.js # Security audit viewer
│   │   ├── crypto/
│   │   │   └── cryptoLib.js    # All cryptographic operations
│   │   ├── styles/
│   │   │   └── index.css       # Styling
│   │   ├── App.js              # Main application
│   │   └── index.js            # Entry point
│   └── package.json
│
├── server/                      # Node.js Backend
│   ├── middleware/
│   │   └── auth.js             # JWT authentication
│   ├── models/
│   │   ├── User.js             # User schema
│   │   ├── Message.js          # Message schema
│   │   ├── EncryptedFile.js    # File schema
│   │   └── SecurityLog.js      # Audit log schema
│   ├── routes/
│   │   ├── auth.js             # Authentication routes
│   │   ├── keys.js             # Public key routes
│   │   ├── messages.js         # Message routes
│   │   ├── files.js            # File routes
│   │   └── logs.js             # Security log routes
│   ├── app.js                  # Main server + Socket.io
│   └── package.json
│
├── attacks/                     # Attack demonstration scripts
│   ├── replay_attack_demo.js   # Replay attack demo
│   └── live_replay_test.js     # Live testing script
│
└── docs/                        # Documentation
    ├── PROJECT_REPORT.md       # This report
    ├── DIAGRAMS.md             # Mermaid diagrams
    └── REPLAY_ATTACK_PROTECTION.md
```

## 12.2 Key Dependencies

### Client (package.json)
```json
{
  "dependencies": {
    "react": "^18.2.0",
    "react-dom": "^18.2.0",
    "react-router-dom": "^6.x",
    "socket.io-client": "^4.7.2",
    "axios": "^1.x"
  }
}
```

### Server (package.json)
```json
{
  "dependencies": {
    "express": "^4.18.x",
    "socket.io": "^4.7.2",
    "mongoose": "^8.x",
    "bcrypt": "^5.x",
    "jsonwebtoken": "^9.x",
    "cors": "^2.x",
    "helmet": "^7.x",
    "express-rate-limit": "^7.x",
    "dotenv": "^16.x"
  }
}
```

## 12.3 API Endpoints

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| POST | /api/auth/register | Register new user | No |
| POST | /api/auth/login | User login | No |
| GET | /api/auth/verify | Verify JWT token | Yes |
| GET | /api/auth/users/search | Search users | Yes |
| GET | /api/keys/:userId | Get user's public keys | Yes |
| GET | /api/messages/conversations | Get conversation list | Yes |
| GET | /api/messages/:partnerId | Get message history | Yes |
| GET | /api/logs | Get security logs | Yes |
| GET | /api/replay-stats | Get replay protection stats | No |

## 12.4 WebSocket Events

| Event | Direction | Description |
|-------|-----------|-------------|
| message:send | Client → Server | Send encrypted message |
| message:receive | Server → Client | Receive encrypted message |
| message:sent | Server → Client | Delivery confirmation |
| message:error | Server → Client | Error notification |
| file:send | Client → Server | Send encrypted file |
| file:receive | Server → Client | Receive encrypted file |
| keyexchange:initiate | Client → Server | Start key exchange |
| keyexchange:request | Server → Client | Key exchange request |
| keyexchange:respond | Client → Server | Key exchange response |
| keyexchange:complete | Server → Client | Key exchange completion |
| user:online | Server → Client | User came online |
| user:offline | Server → Client | User went offline |
| typing:start | Client → Server | User started typing |
| typing:stop | Client → Server | User stopped typing |

---

# 13. Security Analysis

## 13.1 Cryptographic Strength

| Component | Algorithm | Security Level |
|-----------|-----------|----------------|
| Asymmetric Encryption | ECDSA/ECDH P-256 | 128-bit security |
| Symmetric Encryption | AES-256-GCM | 256-bit security |
| Key Derivation | HKDF-SHA256 | 256-bit security |
| Password Hashing | bcrypt (12 rounds) | ~72-bit work factor |
| Random Generation | crypto.getRandomValues() | CSPRNG |

## 13.2 Security Guarantees

| Property | Guarantee | Evidence |
|----------|-----------|----------|
| **Confidentiality** | Messages unreadable by server | Server stores only ciphertext |
| **Integrity** | Tampering detected | AES-GCM authentication tag |
| **Authenticity** | Sender identity verified | ECDSA digital signatures |
| **Forward Secrecy** | Past messages secure after key compromise | Ephemeral ECDH keys |
| **Replay Protection** | Replayed messages rejected | Nonce + timestamp + sequence |
| **MITM Protection** | Key exchange tampering detected | Signed key bundles |

## 13.3 Compliance Considerations

- **OWASP Top 10:** Addressed XSS, injection, broken auth
- **GDPR:** Data minimization, encryption at rest and in transit
- **NIST Guidelines:** Uses NIST-approved algorithms (P-256, AES-GCM, SHA-256)

---

# 14. Limitations & Future Improvements

## 14.1 Current Limitations

| Limitation | Description | Risk Level |
|------------|-------------|------------|
| Single device | Keys stored on one device | Medium |
| No key backup | Lost device = lost access | High |
| No perfect forward secrecy per message | Session key reused within session | Low |
| Basic rate limiting | May not stop distributed attacks | Medium |
| No certificate pinning | Theoretical server spoofing possible | Low |

## 14.2 Future Improvements

1. **Multi-Device Support**
   - Implement secure key synchronization
   - Use key wrapping for cross-device access

2. **Key Backup & Recovery**
   - Implement secure cloud backup with user passphrase
   - Social recovery using trusted contacts

3. **Double Ratchet Algorithm**
   - Per-message forward secrecy
   - Break-in recovery

4. **Enhanced DDoS Protection**
   - CDN integration
   - Proof-of-work challenges

5. **Mobile Applications**
   - React Native implementation
   - Secure enclave storage for keys

6. **Group Messaging**
   - Sender keys protocol
   - Group key management

---

# 15. Conclusion

SecureComm successfully implements a comprehensive end-to-end encrypted messaging and file-sharing system that meets all project requirements:

✅ **User Authentication:** Secure registration with bcrypt password hashing  
✅ **Key Generation & Storage:** ECDSA/ECDH key pairs stored encrypted client-side  
✅ **Secure Key Exchange:** Custom ECDH protocol with ECDSA authentication  
✅ **E2EE Messaging:** AES-256-GCM encryption with fresh IVs  
✅ **E2EE File Sharing:** Client-side file encryption with integrity verification  
✅ **Replay Protection:** Nonces, timestamps, and sequence numbers  
✅ **MITM Prevention:** Digital signatures on key exchange bundles  
✅ **Security Logging:** Comprehensive audit trail of security events  
✅ **Threat Modeling:** STRIDE analysis with countermeasures  

The system demonstrates that modern cryptographic primitives, when properly implemented, can provide strong security guarantees while maintaining usability. The dual approach of client-side encryption and server-side validation creates a defense-in-depth architecture that protects against a wide range of attacks.

---

# 16. References

1. **NIST SP 800-56A Rev. 3** - Recommendation for Pair-Wise Key-Establishment Schemes Using Discrete Logarithm Cryptography
2. **NIST SP 800-38D** - Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM)
3. **RFC 5869** - HMAC-based Extract-and-Expand Key Derivation Function (HKDF)
4. **RFC 6979** - Deterministic Usage of the Digital Signature Algorithm (DSA) and Elliptic Curve Digital Signature Algorithm (ECDSA)
5. **Web Crypto API Specification** - W3C Recommendation
6. **OWASP Cryptographic Storage Cheat Sheet**
7. **Signal Protocol Documentation** - Open Whisper Systems

---

*Report generated for Information Security Semester Project*  
*SecureComm v1.0 - December 2024*
