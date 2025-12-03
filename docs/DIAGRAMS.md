# SecureComm System Diagrams (Mermaid Code)

This file contains all the Mermaid diagram codes for the SecureComm project.
Copy these codes into any Mermaid-compatible editor (VS Code, GitHub, Notion, etc.) to render the diagrams.

---

## 1. High-Level System Architecture

```mermaid
graph TB
    subgraph "Client A (Browser)"
        A1[React App]
        A2[Web Crypto API]
        A3[localStorage<br/>Encrypted Keys]
        A4[sessionStorage<br/>Session Keys]
    end
    
    subgraph "Server (Node.js)"
        S1[Express.js]
        S2[Socket.io]
        S3[JWT Auth]
        S4[Rate Limiter]
    end
    
    subgraph "Database (MongoDB)"
        D1[Users Collection<br/>Public Keys Only]
        D2[Messages Collection<br/>Encrypted Only]
        D3[Security Logs]
        D4[Encrypted Files]
    end
    
    subgraph "Client B (Browser)"
        B1[React App]
        B2[Web Crypto API]
        B3[localStorage<br/>Encrypted Keys]
        B4[sessionStorage<br/>Session Keys]
    end
    
    A1 <-->|HTTPS/WSS| S1
    B1 <-->|HTTPS/WSS| S1
    
    A1 --> A2
    A2 --> A3
    A2 --> A4
    
    B1 --> B2
    B2 --> B3
    B2 --> B4
    
    S1 --> S2
    S1 --> S3
    S1 --> S4
    
    S1 --> D1
    S1 --> D2
    S1 --> D3
    S1 --> D4
```

---

## 2. Key Exchange Protocol Flow

```mermaid
sequenceDiagram
    participant Alice
    participant Server
    participant Bob
    
    Note over Alice: Generate ephemeral<br/>ECDH key pair
    
    Alice->>Alice: Bundle = {ephA_pub, idA_pub, timestamp}
    Alice->>Alice: Signature = Sign(Bundle, idA_priv)
    
    Alice->>Server: KeyExchange Request<br/>{Bundle, Signature, recipientId: Bob}
    
    Server->>Bob: Forward Request
    
    Note over Bob: Verify timestamp<br/>freshness
    Bob->>Bob: Verify Signature<br/>using idA_pub
    
    alt Signature Invalid
        Bob-->>Alice: Error: Invalid Signature
    else Signature Valid
        Note over Bob: Generate ephemeral<br/>ECDH key pair
        Bob->>Bob: SharedSecret = ECDH(ephB_priv, ephA_pub)
        Bob->>Bob: SessionKey = HKDF(SharedSecret, salt)
        Bob->>Bob: Response = {ephB_pub, idB_pub, salt, timestamp}
        Bob->>Bob: Signature = Sign(Response, idB_priv)
        
        Bob->>Server: KeyExchange Response<br/>{Response, Signature}
        
        Server->>Alice: Forward Response
        
        Alice->>Alice: Verify Bob's Signature
        Alice->>Alice: SharedSecret = ECDH(ephA_priv, ephB_pub)
        Alice->>Alice: SessionKey = HKDF(SharedSecret, salt)
        
        Alice->>Server: Confirmation {status: "ok"}
        Server->>Bob: Forward Confirmation
        
        Note over Alice,Bob: Both parties now share<br/>the same session key
    end
```

---

## 3. Message Encryption Flow

```mermaid
flowchart TD
    subgraph "Sender (Alice)"
        A1[Plain Text Message] --> A2[Generate Random IV<br/>96 bits]
        A2 --> A3[Generate Nonce<br/>256 bits]
        A3 --> A4[Get Timestamp<br/>Date.now]
        A4 --> A5[Get Sequence Number]
        A5 --> A6[Create Payload<br/>content + metadata]
        A6 --> A7[Encrypt with AES-256-GCM<br/>using Session Key]
        A7 --> A8[Encrypted Message<br/>+ IV + Nonce + Timestamp + Seq]
    end
    
    subgraph "Server"
        S1[Receive Message] --> S2{Validate Replay<br/>Protection}
        S2 -->|Valid| S3[Store in MongoDB]
        S3 --> S4[Forward to Recipient]
        S2 -->|Invalid| S5[Reject Message<br/>Log Security Event]
    end
    
    subgraph "Receiver (Bob)"
        R1[Receive Encrypted Message] --> R2[Decrypt with AES-256-GCM]
        R2 --> R3[Parse Payload]
        R3 --> R4{Verify Replay<br/>Protection}
        R4 -->|Valid| R5[Display Message]
        R4 -->|Invalid| R6[Block Message<br/>Show Warning]
    end
    
    A8 --> S1
    S4 --> R1
```

---

## 4. Replay Attack Protection Layers

```mermaid
flowchart TD
    subgraph "Incoming Message"
        M[Message with:<br/>- Nonce<br/>- Timestamp<br/>- Sequence Number]
    end
    
    subgraph "Layer 1: Nonce Check"
        N1{Is nonce in cache?}
        N1 -->|Yes| N2[REJECT:<br/>Duplicate Nonce]
        N1 -->|No| N3[Pass to Layer 2]
    end
    
    subgraph "Layer 2: Timestamp Check"
        T1{Is timestamp<br/>within 5 min window?}
        T1 -->|No - Too Old| T2[REJECT:<br/>Expired Message]
        T1 -->|No - Future| T3[REJECT:<br/>Future Timestamp]
        T1 -->|Yes| T4[Pass to Layer 3]
    end
    
    subgraph "Layer 3: Sequence Check"
        S1{Is sequence ><br/>last received?}
        S1 -->|No| S2[REJECT:<br/>Invalid Sequence]
        S1 -->|Yes| S3[Pass to Final]
    end
    
    subgraph "Final Processing"
        F1[Record Nonce in Cache]
        F2[Update Sequence Tracker]
        F3[ACCEPT Message]
    end
    
    M --> N1
    N3 --> T1
    T4 --> S1
    S3 --> F1
    F1 --> F2
    F2 --> F3
    
    N2 --> LOG[Log: REPLAY_ATTACK_DETECTED]
    T2 --> LOG
    T3 --> LOG
    S2 --> LOG
```

---

## 5. MITM Attack Prevention

```mermaid
sequenceDiagram
    participant Alice
    participant Eve as Eve (Attacker)
    participant Bob
    
    Note over Eve: Eve intercepts<br/>communication
    
    rect rgb(255, 200, 200)
        Note over Alice,Bob: Attack Scenario (Without Signatures)
        Alice->>Eve: g^a (Alice's public key)
        Eve->>Bob: g^e1 (Eve's public key)
        Bob->>Eve: g^b (Bob's public key)
        Eve->>Alice: g^e2 (Eve's public key)
        Note over Eve: Eve has two keys:<br/>Key_AE and Key_EB<br/>Can decrypt all traffic!
    end
    
    rect rgb(200, 255, 200)
        Note over Alice,Bob: Our Protocol (With Signatures)
        Alice->>Alice: Sign(g^a, Alice_priv)
        Alice->>Eve: g^a + Signature
        Eve->>Eve: Cannot forge<br/>Alice's signature!
        Eve--xBob: Modified key<br/>DETECTED!
        Bob->>Bob: Verify Signature<br/>FAILS if modified
        Note over Bob: Key exchange<br/>ABORTED
    end
```

---

## 6. User Registration Flow

```mermaid
flowchart TD
    A[User enters<br/>username, email, password] --> B[Client: Generate<br/>ECDSA Key Pair]
    B --> C[Client: Generate<br/>ECDH Key Pair]
    C --> D[Client: Encrypt private keys<br/>with PBKDF2 + AES-GCM]
    D --> E[Client: Store encrypted keys<br/>in localStorage]
    E --> F[Client: Send registration request<br/>username, email, password hash,<br/>PUBLIC keys only]
    F --> G[Server: Hash password<br/>with bcrypt 12 rounds]
    G --> H[Server: Store user in MongoDB<br/>public keys + password hash]
    H --> I[Server: Generate JWT]
    I --> J[Server: Log AUTH_REGISTER event]
    J --> K[Return JWT to client]
    K --> L[Client: Store JWT]
    L --> M[Redirect to Chat]
```

---

## 7. File Encryption Flow

```mermaid
flowchart TD
    subgraph "Client Side Encryption"
        F1[Select File] --> F2[Read as ArrayBuffer]
        F2 --> F3[Generate Salt<br/>32 bytes random]
        F3 --> F4[Derive File Key<br/>HKDF from Session Key]
        F4 --> F5[Compute SHA-256 Hash<br/>of file data]
        F5 --> F6[Create Metadata<br/>filename, type, size, hash]
        F6 --> F7[Encrypt Metadata<br/>AES-256-GCM]
        F7 --> F8[Encrypt File Data<br/>AES-256-GCM]
        F8 --> F9[Encrypted Package<br/>salt + encrypted meta + encrypted data]
    end
    
    subgraph "Server Storage"
        S1[Receive Encrypted Package]
        S2[Store in MongoDB<br/>No decryption possible]
    end
    
    subgraph "Client Side Decryption"
        D1[Download Encrypted Package]
        D2[Derive File Key<br/>using same salt]
        D3[Decrypt Metadata]
        D4[Decrypt File Data]
        D5[Verify SHA-256 Hash]
        D6{Hash Match?}
        D7[Save File to Device]
        D8[Reject: Integrity<br/>Check Failed]
    end
    
    F9 --> S1
    S1 --> S2
    S2 --> D1
    D1 --> D2
    D2 --> D3
    D3 --> D4
    D4 --> D5
    D5 --> D6
    D6 -->|Yes| D7
    D6 -->|No| D8
```

---

## 8. STRIDE Threat Model

```mermaid
mindmap
    root((SecureComm<br/>Threats))
        Spoofing
            User Impersonation
                Countermeasure: JWT + bcrypt
            Session Hijacking
                Countermeasure: Token expiration
            Key Exchange Impersonation
                Countermeasure: ECDSA signatures
        Tampering
            Message Modification
                Countermeasure: AES-GCM auth tag
            Key Bundle Modification
                Countermeasure: Digital signatures
            File Corruption
                Countermeasure: SHA-256 hash
        Repudiation
            Deny Sending Message
                Countermeasure: Signed messages
            Deny Key Exchange
                Countermeasure: Audit logs
        Information Disclosure
            Message Content Exposure
                Countermeasure: E2EE
            Private Key Theft
                Countermeasure: Encrypted storage
            Password Theft
                Countermeasure: bcrypt hashing
        Denial of Service
            API Flooding
                Countermeasure: Rate limiting
            Large File Upload
                Countermeasure: 50MB limit
        Elevation of Privilege
            Access Others Messages
                Countermeasure: Auth checks
            JWT Manipulation
                Countermeasure: Signature verify
```

---

## 9. Database Schema

```mermaid
erDiagram
    USERS ||--o{ MESSAGES : sends
    USERS ||--o{ MESSAGES : receives
    USERS ||--o{ SECURITY_LOGS : triggers
    USERS ||--o{ ENCRYPTED_FILES : uploads
    
    USERS {
        ObjectId _id PK
        string username UK
        string email UK
        string passwordHash
        object publicKeys
        string status
        object security
        date createdAt
    }
    
    MESSAGES {
        ObjectId _id PK
        ObjectId senderId FK
        ObjectId recipientId FK
        string encryptedPayload
        string iv
        string nonce UK
        number timestamp
        number sequenceNumber
        string status
        date createdAt
    }
    
    ENCRYPTED_FILES {
        ObjectId _id PK
        ObjectId senderId FK
        ObjectId recipientId FK
        string salt
        object encryptedMetadata
        object encryptedData
        date createdAt
    }
    
    SECURITY_LOGS {
        ObjectId _id PK
        string eventType
        string severity
        ObjectId userId FK
        string username
        ObjectId targetUserId FK
        object request
        object details
        string result
        date timestamp
    }
```

---

## 10. Authentication Flow

```mermaid
sequenceDiagram
    participant User
    participant Client
    participant Server
    participant MongoDB
    
    User->>Client: Enter credentials
    Client->>Server: POST /api/auth/login<br/>{username, password}
    
    Server->>MongoDB: Find user by username
    MongoDB-->>Server: User document
    
    alt User not found
        Server-->>Client: 401 Invalid credentials
    else User found
        Server->>Server: bcrypt.compare(password, hash)
        
        alt Password invalid
            Server->>MongoDB: Increment failedAttempts
            alt Attempts >= 5
                Server->>MongoDB: Lock account for 15 min
                Server-->>Client: 423 Account locked
            else
                Server-->>Client: 401 Invalid credentials
            end
        else Password valid
            Server->>MongoDB: Reset failedAttempts
            Server->>MongoDB: Update lastLoginAt
            Server->>Server: Generate JWT<br/>{userId, username, exp: 24h}
            Server->>MongoDB: Log AUTH_LOGIN_SUCCESS
            Server-->>Client: 200 {token, user}
            Client->>Client: Store JWT in localStorage
            Client->>User: Redirect to Chat
        end
    end
```

---

## 11. Session Key Derivation

```mermaid
flowchart TD
    subgraph "ECDH Key Agreement"
        A1[Alice's Ephemeral<br/>Private Key] --> E1[ECDH Algorithm]
        B1[Bob's Ephemeral<br/>Public Key] --> E1
        E1 --> S1[Shared Secret<br/>256 bits]
    end
    
    subgraph "HKDF Key Derivation"
        S1 --> H1[Import as<br/>HKDF Key Material]
        SALT[Random Salt<br/>32 bytes] --> H2[HKDF-SHA256]
        INFO[Context Info<br/>'SecureComm-E2EE-v1'] --> H2
        H1 --> H2
        H2 --> SK[Session Key<br/>AES-256-GCM<br/>256 bits]
    end
    
    subgraph "Key Usage"
        SK --> U1[Encrypt Messages]
        SK --> U2[Decrypt Messages]
        SK --> U3[Derive File Keys]
    end
```

---

## 12. Complete Message Flow

```mermaid
sequenceDiagram
    participant Alice
    participant AliceCrypto as Alice's<br/>Web Crypto
    participant Server
    participant BobCrypto as Bob's<br/>Web Crypto
    participant Bob
    
    Note over Alice: Type message "Hello!"
    
    Alice->>AliceCrypto: Encrypt message
    
    rect rgb(230, 230, 250)
        Note over AliceCrypto: Encryption Process
        AliceCrypto->>AliceCrypto: Generate IV (12 bytes)
        AliceCrypto->>AliceCrypto: Generate Nonce (32 bytes)
        AliceCrypto->>AliceCrypto: Get timestamp
        AliceCrypto->>AliceCrypto: Get next sequence #
        AliceCrypto->>AliceCrypto: Create payload JSON
        AliceCrypto->>AliceCrypto: AES-256-GCM encrypt
    end
    
    AliceCrypto-->>Alice: Encrypted bundle
    
    Alice->>Server: WebSocket: message:send<br/>{ciphertext, iv, nonce, timestamp, seq}
    
    rect rgb(255, 250, 230)
        Note over Server: Replay Protection
        Server->>Server: Check nonce uniqueness
        Server->>Server: Validate timestamp window
        Server->>Server: Verify sequence number
    end
    
    alt Replay Detected
        Server-->>Alice: message:error<br/>Replay attack blocked
        Server->>Server: Log CRITICAL event
    else Valid Message
        Server->>Server: Store encrypted message
        Server->>Server: Log MESSAGE_SENT
        Server->>Bob: WebSocket: message:receive
        
        Bob->>BobCrypto: Decrypt message
        
        rect rgb(230, 250, 230)
            Note over BobCrypto: Decryption Process
            BobCrypto->>BobCrypto: AES-256-GCM decrypt
            BobCrypto->>BobCrypto: Parse payload
            BobCrypto->>BobCrypto: Verify nonce/timestamp/seq
        end
        
        BobCrypto-->>Bob: "Hello!"
        Note over Bob: Display message
    end
```

---

## How to Use These Diagrams

### Option 1: VS Code with Mermaid Extension
1. Install "Markdown Preview Mermaid Support" extension
2. Open this file in VS Code
3. Press `Ctrl+Shift+V` to preview

### Option 2: GitHub/GitLab
- Simply push this file to your repository
- GitHub/GitLab will automatically render the diagrams

### Option 3: Mermaid Live Editor
1. Go to https://mermaid.live
2. Paste any diagram code
3. Export as PNG/SVG

### Option 4: Notion
1. Create a new code block
2. Select "Mermaid" as the language
3. Paste the diagram code

### Option 5: Draw.io/diagrams.net
1. Insert → Advanced → Mermaid
2. Paste the code

---

*Diagrams created for SecureComm E2EE Messaging System*  
*December 2024*
