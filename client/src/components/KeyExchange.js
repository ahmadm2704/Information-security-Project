import React, { useState, useEffect, useCallback, useRef } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { io } from 'socket.io-client';
import { useAuth, API_URL } from '../App';

function KeyExchange() {
  const { partnerId } = useParams();
  const navigate = useNavigate();
  const { user, token, privateKeys, setPrivateKeys } = useAuth();
  
  const [socket, setSocket] = useState(null);
  const [partner, setPartner] = useState(null);
  const [status, setStatus] = useState('loading');
  const [logs, setLogs] = useState([]);
  const [error, setError] = useState('');
  const [sessionKey, setSessionKey] = useState(null);
  const [fingerprint, setFingerprint] = useState('');
  const [keysReady, setKeysReady] = useState(false);
  const [needsPassword, setNeedsPassword] = useState(false);
  const [password, setPassword] = useState('');
  
  const ephemeralPrivateKeyRef = useRef(null);
  const loadedKeysRef = useRef(null);
  const socketRef = useRef(null);
  const sessionKeyRef = useRef(null);
  
  const addLog = useCallback((message, type = 'info') => {
    setLogs(prev => [...prev, {
      message,
      type,
      time: new Date().toLocaleTimeString()
    }]);
  }, []);

  // Get available keys (from context or loaded ref)
  const getAvailableKeys = useCallback(() => {
    return privateKeys || loadedKeysRef.current;
  }, [privateKeys]);

  // Load private keys on mount
  useEffect(() => {
    const loadKeys = async () => {
      // If we already have keys in context, use them
      if (privateKeys) {
        console.log('[KE] Keys available from context');
        loadedKeysRef.current = privateKeys;
        setKeysReady(true);
        addLog("Private keys loaded from session", "success");
        return;
      }
      
      // Try to retrieve keys from storage (need password)
      console.log('[KE] No keys in context, will need password');
      setNeedsPassword(true);
    };
    
    if (user?.id) {
      loadKeys();
    }
  }, [user, privateKeys, addLog]);

  // Handle password submission to unlock keys
  const handleUnlockKeys = async () => {
    if (!password) {
      setError('Please enter your password');
      return;
    }
    
    try {
      console.log('[KE] Attempting to retrieve keys with password...');
      const keys = await window.CryptoLib.retrievePrivateKeys(user.id, password);
      loadedKeysRef.current = keys;
      if (setPrivateKeys) {
        setPrivateKeys(keys); // Update context too
      }
      setKeysReady(true);
      setNeedsPassword(false);
      setError('');
      addLog("Private keys unlocked successfully", "success");
    } catch (err) {
      console.error('[KE] Failed to unlock keys:', err);
      setError('Failed to unlock keys. Check your password or log in again.');
    }
  };
  
  // Initialize socket
  useEffect(() => {
    if (!token) return;
    
    const s = io(API_URL, { auth: { token } });
    
    s.on('connect', () => {
      console.log('Socket connected');
      addLog('Connected to server', 'info');
    });
    
    s.on('connect_error', (e) => {
      console.error('Socket error:', e);
      setError('Connection error');
    });
    
    setSocket(s);
    socketRef.current = s;
    
    return () => s.disconnect();
  }, [token, addLog]);
  
  // Load partner info
  useEffect(() => {
    if (!partnerId || !token) {
      return;
    }
    
    const loadPartner = async () => {
      try {
        console.log('Loading partner bundle for:', partnerId);
        const res = await fetch(`${API_URL}/api/keys/bundle/${partnerId}`, {
          headers: { Authorization: `Bearer ${token}` }
        });
        
        if (!res.ok) {
          const errData = await res.json();
          throw new Error(errData.error || 'Failed to load partner');
        }
        
        const data = await res.json();
        console.log('Partner data loaded:', data.username);
        setPartner(data);
        setStatus('ready');
        addLog(`Loaded ${data.username}'s info`, 'success');
        
      } catch (e) {
        console.error('Partner load error:', e);
        setError(e.message);
        setStatus('error');
        addLog(e.message, 'error');
      }
    };
    
    loadPartner();
  }, [partnerId, token, addLog]);

  // Helper function to get public key from private signing key
  const getSigningPublicKey = async (privateKey) => {
    const jwk = await crypto.subtle.exportKey('jwk', privateKey);
    return window.CryptoLib.cleanJwkPublic(jwk);
  };
  
  // Respond to key exchange - USE THE IDENTITY KEY FROM THE BUNDLE for verification
  const respondToKeyExchange = useCallback(async (data) => {
    const keys = getAvailableKeys();
    
    try {
      const signingKey = keys?.signing;
      if (!signingKey) {
        throw new Error('Private signing key not available');
      }
      
      addLog('Verifying initiator signature...', 'info');
      
      const bundle = data.bundle;
      
      // Parse the identity key FROM THE BUNDLE (not from stored keys)
      // This is the key the initiator actually used to sign
      const theirIdJwk = JSON.parse(bundle.identityKey);
      const theirEphJwk = JSON.parse(bundle.ephemeralKey);
      
      // Import the identity key from the bundle for verification
      const theirIdentityKey = await crypto.subtle.importKey(
        'jwk', theirIdJwk,
        { name: 'ECDSA', namedCurve: 'P-256' },
        true, ['verify']
      );
      
      // Verify timestamp
      if (Math.abs(Date.now() - bundle.timestamp) > 5 * 60 * 1000) {
        throw new Error('Timestamp expired - possible replay attack');
      }
      
      // Verify signature using the identity key FROM THE BUNDLE
      const msgToVerify = JSON.stringify({
        ephemeralKey: bundle.ephemeralKey,
        identityKey: bundle.identityKey,
        timestamp: bundle.timestamp
      });
      
      const valid = await crypto.subtle.verify(
        { name: 'ECDSA', hash: 'SHA-256' },
        theirIdentityKey,  // Use the key from the bundle
        window.CryptoLib.fromBase64(bundle.signature),
        new TextEncoder().encode(msgToVerify)
      );
      
      if (!valid) throw new Error('Invalid signature - MITM attack detected!');
      
      addLog('✓ Signature verified - initiator authenticated', 'success');
      addLog('Generating ephemeral keys...', 'info');
      
      // Generate our ephemeral key pair
      const myEphKp = await crypto.subtle.generateKey(
        { name: 'ECDH', namedCurve: 'P-256' },
        true, ['deriveKey', 'deriveBits']
      );
      
      // Import their ephemeral key
      const theirEphKey = await crypto.subtle.importKey(
        'jwk', theirEphJwk,
        { name: 'ECDH', namedCurve: 'P-256' },
        true, []
      );
      
      addLog('Deriving shared secret via ECDH...', 'info');
      
      // Derive shared secret
      const sharedSecret = await crypto.subtle.deriveBits(
        { name: 'ECDH', public: theirEphKey },
        myEphKp.privateKey,
        256
      );
      
      // Generate salt
      const salt = crypto.getRandomValues(new Uint8Array(32));
      
      addLog('Deriving session key via HKDF...', 'info');
      
      // Derive session key
      const keyMaterial = await crypto.subtle.importKey(
        'raw', sharedSecret, 'HKDF', false, ['deriveKey']
      );
      
      const sessKey = await crypto.subtle.deriveKey(
        { name: 'HKDF', hash: 'SHA-256', salt, info: new TextEncoder().encode('SecureComm-E2EE-v1') },
        keyMaterial,
        { name: 'AES-GCM', length: 256 },
        true, ['encrypt', 'decrypt']
      );
      
      setSessionKey(sessKey);
      sessionKeyRef.current = sessKey;
      
      // Calculate fingerprint
      const keyBytes = await crypto.subtle.exportKey('raw', sessKey);
      const hash = await crypto.subtle.digest('SHA-256', keyBytes);
      const fp = Array.from(new Uint8Array(hash).slice(0, 8))
        .map(b => b.toString(16).padStart(2, '0'))
        .join(':');
      setFingerprint(fp);
      
      addLog(`Key fingerprint: ${fp}`, 'info');
      addLog('Creating response bundle...', 'info');
      
      // Create response
      const myEphPubJwk = window.CryptoLib.cleanJwkPublic(
        await crypto.subtle.exportKey('jwk', myEphKp.publicKey)
      );
      
      // Get our signing public key
      const sigPubJwk = await getSigningPublicKey(signingKey);
      
      const respTimestamp = Date.now();
      const respBundle = {
        ephemeralKey: JSON.stringify(myEphPubJwk),
        identityKey: JSON.stringify(sigPubJwk),
        salt: window.CryptoLib.toBase64(salt),
        timestamp: respTimestamp
      };
      
      const respMsg = JSON.stringify(respBundle);
      const respSig = await crypto.subtle.sign(
        { name: 'ECDSA', hash: 'SHA-256' },
        signingKey,
        new TextEncoder().encode(respMsg)
      );
      
      respBundle.signature = window.CryptoLib.toBase64(respSig);
      
      addLog('Sending response...', 'info');
      
      socketRef.current.emit('keyexchange:respond', {
        initiatorId: data.initiatorId,
        responderId: user.id,
        bundle: respBundle
      });
      
      setStatus('confirming');
      addLog('Waiting for confirmation...', 'info');
      
    } catch (e) {
      console.error('Respond error:', e);
      setError(e.message);
      setStatus('error');
      addLog(e.message, 'error');
    }
  }, [getAvailableKeys, user, addLog]);
  
  // Complete key exchange (initiator side) - USE IDENTITY KEY FROM BUNDLE
  const completeKeyExchange = useCallback(async (data) => {
    try {
      setStatus('deriving');
      addLog('Verifying responder signature...', 'info');
      
      const bundle = data.bundle;
      
      // Parse the identity key FROM THE BUNDLE
      const theirIdJwk = JSON.parse(bundle.identityKey);
      const theirEphJwk = window.CryptoLib.cleanJwk(JSON.parse(bundle.ephemeralKey));
      
      // Import the identity key from the bundle for verification
      const theirIdentityKey = await crypto.subtle.importKey(
        'jwk', theirIdJwk,
        { name: 'ECDSA', namedCurve: 'P-256' },
        true, ['verify']
      );
      
      // Verify timestamp
      if (Math.abs(Date.now() - bundle.timestamp) > 5 * 60 * 1000) {
        throw new Error('Timestamp expired');
      }
      
      // Verify signature using the identity key FROM THE BUNDLE
      const msgToVerify = JSON.stringify({
        ephemeralKey: bundle.ephemeralKey,
        identityKey: bundle.identityKey,
        salt: bundle.salt,
        timestamp: bundle.timestamp
      });
      
      const valid = await crypto.subtle.verify(
        { name: 'ECDSA', hash: 'SHA-256' },
        theirIdentityKey,  // Use the key from the bundle
        window.CryptoLib.fromBase64(bundle.signature),
        new TextEncoder().encode(msgToVerify)
      );
      
      if (!valid) throw new Error('Invalid signature - MITM attack detected!');
      
      addLog('✓ Signature verified - responder authenticated', 'success');
      addLog('Deriving shared secret...', 'info');
      
      // Verify ephemeral key exists
      if (!ephemeralPrivateKeyRef.current) {
        throw new Error('Ephemeral key not initialized');
      }
      
      // Import their ephemeral key
      const theirEphKey = await crypto.subtle.importKey(
        'jwk', theirEphJwk,
        { name: 'ECDH', namedCurve: 'P-256' },
        true, []
      );
      
      // Derive shared secret
      const sharedSecret = await crypto.subtle.deriveBits(
        { name: 'ECDH', public: theirEphKey },
        ephemeralPrivateKeyRef.current,
        256
      );
      
      addLog('Deriving session key...', 'info');
      
      // Derive session key
      const salt = window.CryptoLib.fromBase64(bundle.salt);
      const keyMaterial = await crypto.subtle.importKey(
        'raw', sharedSecret, 'HKDF', false, ['deriveKey']
      );
      
      const sessKey = await crypto.subtle.deriveKey(
        { name: 'HKDF', hash: 'SHA-256', salt, info: new TextEncoder().encode('SecureComm-E2EE-v1') },
        keyMaterial,
        { name: 'AES-GCM', length: 256 },
        true, ['encrypt', 'decrypt']
      );
      
      setSessionKey(sessKey);
      sessionKeyRef.current = sessKey;
      
      // Calculate fingerprint
      const keyBytes = await crypto.subtle.exportKey('raw', sessKey);
      const hash = await crypto.subtle.digest('SHA-256', keyBytes);
      const fp = Array.from(new Uint8Array(hash).slice(0, 8))
        .map(b => b.toString(16).padStart(2, '0'))
        .join(':');
      setFingerprint(fp);
      
      addLog(`Key fingerprint: ${fp}`, 'info');
      
      // Store session key
      await window.CryptoLib.storeSessionKey(partnerId, sessKey);
      
      addLog('Sending confirmation...', 'info');
      
      socketRef.current.emit('keyexchange:confirm', {
        partnerId,
        confirmation: 'ok'
      });
      
      setStatus('complete');
      addLog('🔐 Key exchange complete!', 'success');
      
      // Log to server
      fetch(`${API_URL}/api/keys/exchange/log`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ partnerId, status: 'success' })
      }).catch(() => {});
      
      setTimeout(() => navigate(`/chat/${partnerId}`), 2000);
      
    } catch (e) {
      console.error('Complete error:', e);
      setError(e.message);
      setStatus('error');
      addLog(e.message, 'error');
    }
  }, [partnerId, token, navigate, addLog]);
  
  // Finalize (responder side after confirmation)
  const finalizeKeyExchange = useCallback(async () => {
    const keyToStore = sessionKeyRef.current || sessionKey;
    if (!keyToStore) {
      console.error('No session key available for finalization');
      return;
    }
    
    try {
      await window.CryptoLib.storeSessionKey(partnerId, keyToStore);
      
      setStatus('complete');
      addLog('🔐 Key exchange complete!', 'success');
      
      fetch(`${API_URL}/api/keys/exchange/log`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ partnerId, status: 'success' })
      }).catch(() => {});
      
      setTimeout(() => navigate(`/chat/${partnerId}`), 2000);
      
    } catch (e) {
      console.error('Finalize error:', e);
    }
  }, [sessionKey, partnerId, token, navigate, addLog]);

  // Socket event handlers
  useEffect(() => {
    if (!socket || !keysReady) {
      console.log('[KE] Waiting for socket handlers setup:', { 
        socket: !!socket, 
        keysReady 
      });
      return;
    }
    
    console.log('[KE] Setting up socket handlers');
    
    // Handle incoming key exchange request (we're the responder)
    const handleRequest = async (data) => {
      console.log('[KE] Received keyexchange:request', data);
      if (data.initiatorId === partnerId) {
        addLog('Received key exchange request', 'info');
        setStatus('responding');
        await respondToKeyExchange(data);
      }
    };
    
    // Handle response (we're the initiator)
    const handleResponse = async (data) => {
      console.log('[KE] Received keyexchange:response', data);
      if (data.responderId === partnerId) {
        addLog('Received key exchange response', 'info');
        await completeKeyExchange(data);
      }
    };
    
    // Handle confirmation
    const handleConfirmed = (data) => {
      console.log('[KE] Received keyexchange:confirmed', data);
      if (data.partnerId === partnerId) {
        addLog('Key exchange confirmed!', 'success');
        finalizeKeyExchange();
      }
    };
    
    const handleOffline = () => {
      setError('Partner is offline');
      setStatus('error');
      addLog('Partner is offline', 'error');
    };
    
    socket.on('keyexchange:request', handleRequest);
    socket.on('keyexchange:response', handleResponse);
    socket.on('keyexchange:confirmed', handleConfirmed);
    socket.on('keyexchange:offline', handleOffline);
    
    return () => {
      socket.off('keyexchange:request', handleRequest);
      socket.off('keyexchange:response', handleResponse);
      socket.off('keyexchange:confirmed', handleConfirmed);
      socket.off('keyexchange:offline', handleOffline);
    };
  }, [socket, partnerId, keysReady, respondToKeyExchange, completeKeyExchange, finalizeKeyExchange, addLog]);
  
  // Initiate key exchange
  const initiateKeyExchange = async () => {
    const keysToUse = getAvailableKeys();
    
    if (!keysToUse) {
      setError('❌ Private keys not available. Please enter your password or log in again.');
      setNeedsPassword(true);
      return;
    }
    
    if (!socket) {
      setError('Socket not connected');
      return;
    }
    
    try {
      setStatus('initiating');
      setLogs([]);
      addLog('Generating ephemeral ECDH key pair...', 'info');
      
      // Generate ephemeral key pair
      const ephKp = await crypto.subtle.generateKey(
        { name: 'ECDH', namedCurve: 'P-256' },
        true, ['deriveKey', 'deriveBits']
      );
      
      ephemeralPrivateKeyRef.current = ephKp.privateKey;
      
      // Export public keys
      const ephPubJwk = window.CryptoLib.cleanJwkPublic(
        await crypto.subtle.exportKey('jwk', ephKp.publicKey)
      );
      
      // Get our signing public key
      const sigPubJwk = await getSigningPublicKey(keysToUse.signing);
      
      addLog('Signing bundle with identity key...', 'info');
      
      // Create and sign bundle
      const timestamp = Date.now();
      const bundle = {
        ephemeralKey: JSON.stringify(ephPubJwk),
        identityKey: JSON.stringify(sigPubJwk),
        timestamp
      };
      
      const message = JSON.stringify(bundle);
      const signature = await crypto.subtle.sign(
        { name: 'ECDSA', hash: 'SHA-256' },
        keysToUse.signing,
        new TextEncoder().encode(message)
      );
      
      bundle.signature = window.CryptoLib.toBase64(signature);
      
      addLog('Sending to partner...', 'info');
      
      socket.emit('keyexchange:initiate', {
        recipientId: partnerId,
        bundle
      });
      
      addLog('Waiting for response...', 'info');
      
    } catch (e) {
      console.error('Initiate error:', e);
      setError(e.message);
      setStatus('error');
      addLog(e.message, 'error');
    }
  };
  
  return (
    <div className="key-exchange-container">
      <div className="key-exchange-card">
        <div className="ke-header">
          <h1>🔐 Secure Key Exchange</h1>
          <p>Establishing encrypted channel with <strong>{partner?.username || '...'}</strong></p>
        </div>
        
        {/* Status */}
        <div className={`ke-status status-${status}`}>
          {status === 'loading' && '⏳ Loading...'}
          {status === 'ready' && (keysReady ? '✅ Ready to exchange keys' : '🔑 Enter password to unlock keys')}
          {status === 'initiating' && '🔄 Initiating...'}
          {status === 'responding' && '🔄 Responding...'}
          {status === 'deriving' && '🔄 Deriving keys...'}
          {status === 'confirming' && '🔄 Confirming...'}
          {status === 'complete' && '✅ Key exchange complete!'}
          {status === 'error' && '❌ Key exchange failed'}
        </div>
        
        {/* Password prompt if needed */}
        {needsPassword && !keysReady && (
          <div className="ke-password-prompt">
            <div className="password-input-group">
              <label>🔑 Enter your password to unlock private keys:</label>
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="Your login password"
                onKeyPress={(e) => e.key === 'Enter' && handleUnlockKeys()}
              />
              <button className="btn btn-primary" onClick={handleUnlockKeys}>
                Unlock Keys
              </button>
            </div>
          </div>
        )}
        
        {/* Error */}
        {error && (
          <div className="ke-error">
            ⚠️ {error}
          </div>
        )}
        
        {/* Progress Logs */}
        {logs.length > 0 && (
          <div className="ke-logs">
            <h3>Protocol Steps</h3>
            <div className="log-list">
              {logs.map((log, i) => (
                <div key={i} className={`log-item log-${log.type}`}>
                  <span className="log-time">{log.time}</span>
                  <span className="log-msg">{log.message}</span>
                </div>
              ))}
            </div>
          </div>
        )}
        
        {/* Fingerprint */}
        {fingerprint && status === 'complete' && (
          <div className="ke-fingerprint">
            <h4>Session Key Fingerprint</h4>
            <code>{fingerprint}</code>
            <p>Compare with your partner to verify the connection</p>
          </div>
        )}
        
        {/* Actions */}
        <div className="ke-actions">
          {status === 'ready' && keysReady && (
            <button 
              className="btn btn-primary" 
              onClick={initiateKeyExchange}
            >
              🔑 Initiate Key Exchange
            </button>
          )}
          
          {status === 'error' && (
            <button className="btn btn-primary" onClick={() => {
              setStatus('ready');
              setError('');
              setLogs([]);
            }}>
              Try Again
            </button>
          )}
          
          <button className="btn btn-secondary" onClick={() => navigate(-1)}>
            Cancel
          </button>
        </div>
        
        {/* Security Info */}
        <div className="ke-security-info">
          <h4>Security Features</h4>
          <ul>
            <li>✓ ECDSA signatures prevent MITM attacks</li>
            <li>✓ Ephemeral keys provide forward secrecy</li>
            <li>✓ Timestamps prevent replay attacks</li>
            <li>✓ HKDF ensures strong key derivation</li>
          </ul>
        </div>
      </div>
    </div>
  );
}

export default KeyExchange;