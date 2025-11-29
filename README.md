# SecureComm - End-to-End Encrypted Communication System

A full-featured E2EE messaging application with custom key exchange protocol, digital signatures, and comprehensive security features.

## 🔐 Security Features

- **ECDSA P-256 Digital Signatures** - Prevents MITM attacks
- **ECDH P-256 Key Agreement** - Perfect forward secrecy  
- **AES-256-GCM Encryption** - Authenticated encryption for messages
- **HKDF Key Derivation** - Secure session key generation
- **PBKDF2 Password Hashing** - Secure credential storage (100k iterations)
- **bcrypt** - Server-side password hashing (12 rounds)
- **Replay Attack Protection** - Nonces and timestamps
- **Security Logging** - Comprehensive audit trail

## 📁 Project Structure

```
secure-comm-system/
├── server/
│   ├── app.js              # Main server with Socket.io
│   ├── models/
│   │   ├── User.js         # User with public keys
│   │   ├── Message.js      # Encrypted messages
│   │   ├── SecurityLog.js  # Audit logs
│   │   └── EncryptedFile.js
│   ├── routes/
│   │   ├── auth.js         # Authentication
│   │   ├── keys.js         # Public key bundles
│   │   ├── messages.js     # Message history
│   │   ├── files.js        # File upload/download
│   │   └── logs.js         # Security logs
│   ├── middleware/
│   │   └── auth.js         # JWT authentication
│   └── package.json
│
├── client/
│   ├── src/
│   │   ├── App.js          # Main app with auth context
│   │   ├── components/
│   │   │   ├── Header.js
│   │   │   ├── Login.js
│   │   │   ├── Register.js
│   │   │   ├── Chat.js
│   │   │   ├── KeyExchange.js
│   │   │   ├── FileShare.js
│   │   │   └── SecurityLogs.js
│   │   ├── crypto/
│   │   │   └── cryptoLib.js  # Web Crypto API wrapper
│   │   └── styles/
│   │       └── index.css
│   ├── public/
│   │   └── index.html
│   └── package.json
│
└── README.md
```

## 🚀 Quick Start

### Prerequisites
- Node.js v18 or higher
- MongoDB (local or Atlas)

### 1. Start MongoDB
```bash
mongod
```

### 2. Setup & Start Server
```bash
cd server
npm install
npm start
```
Server runs on http://localhost:5000

### 3. Setup & Start Client
```bash
cd client
npm install
npm start
```
Client runs on http://localhost:3000

## 📱 Using the Application

### Step 1: Register Users
1. Open http://localhost:3000
2. Click "Register" and create an account
3. Open an incognito window and register another user

### Step 2: Start a Conversation
1. In User 1's window, search for User 2's username
2. Click on the user to open the chat

### Step 3: Complete Key Exchange
1. Click "🔑 Start Key Exchange"
2. Wait for the protocol to complete
3. Both users will see "🔐 Encrypted" when ready

### Step 4: Send Encrypted Messages
1. Type your message and press Enter or click Send
2. Messages are encrypted client-side before sending
3. Only the recipient can decrypt them

## 🔑 Key Exchange Protocol

```
Alice (Initiator)                    Bob (Responder)
      │                                    │
      │ 1. Generate ephemeral ECDH keypair │
      │    Sign with identity key          │
      │─────────────────────────────────────>
      │                                    │
      │                                    │ 2. Verify signature
      │                                    │    Generate ephemeral ECDH
      │                                    │    Derive shared secret
      │                                    │    Derive session key (HKDF)
      │                                    │    Sign response
      │<─────────────────────────────────────
      │                                    │
      │ 3. Verify signature                │
      │    Derive session key              │
      │    Send confirmation               │
      │─────────────────────────────────────>
      │                                    │
      │         ✅ Both have same key       │
```

## 🛡️ Security Architecture

### Cryptographic Specifications

| Component | Algorithm | Parameters |
|-----------|-----------|------------|
| Identity Keys | ECDSA | P-256, SHA-256 |
| Key Agreement | ECDH | P-256 |
| Message Encryption | AES-GCM | 256-bit key, 96-bit IV |
| Key Derivation | HKDF | SHA-256 |
| Password Storage (Client) | PBKDF2 | 100,000 iterations |
| Password Storage (Server) | bcrypt | 12 rounds |

### What the Server Sees
- ❌ Never sees plaintext messages
- ❌ Never sees private keys
- ✅ Only sees encrypted ciphertext
- ✅ Public keys for key exchange
- ✅ Metadata (sender, recipient, timestamp)

## 🔧 Configuration

### Server (.env)
```
PORT=5000
MONGODB_URI=mongodb://localhost:27017/securecomm
JWT_SECRET=your-secret-key-change-in-production
CLIENT_URL=http://localhost:3000
```

## 📊 Features

- ✅ User registration with key generation
- ✅ Secure login with bcrypt
- ✅ Real-time messaging via Socket.io
- ✅ Custom key exchange protocol
- ✅ End-to-end encryption
- ✅ Digital signature verification
- ✅ Replay attack protection
- ✅ Security event logging
- ✅ File encryption (client-side)
- ✅ Online/offline status
- ✅ Typing indicators
- ✅ Message history

## 🧪 Testing Key Exchange

1. Open browser DevTools (F12)
2. Go to Console tab
3. Initiate key exchange
4. Watch the protocol steps in the UI
5. Verify both users see the same key fingerprint

## 🔒 Security Considerations

1. **Private keys never leave the device** - Stored encrypted in IndexedDB
2. **Server is untrusted** - Only sees ciphertext
3. **Forward secrecy** - Ephemeral keys for each session
4. **MITM prevention** - Digital signatures verify identity
5. **Replay protection** - Timestamps and nonces

## 📝 License

MIT License

## 👥 For Academic Project

This project demonstrates:
- Hybrid cryptography (asymmetric + symmetric)
- Custom cryptographic protocol design
- Web Crypto API usage
- Real-time secure communication
- Security logging and auditing
