import React, { useState, useEffect, useCallback, useRef } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { io } from 'socket.io-client';
import { useAuth, API_URL } from '../App';

function KeyExchange() {
  const { partnerId } = useParams();
  const navigate = useNavigate();
  const { user, token, privateKeys } = useAuth();
  
  const [socket, setSocket] = useState(null);
  const [partner, setPartner] = useState(null);
  const [partnerIdentityKey, setPartnerIdentityKey] = useState(null);
  const [status, setStatus] = useState('loading');
  const [logs, setLogs] = useState([]);
  const [error, setError] = useState('');
  const [sessionKey, setSessionKey] = useState(null);
  const [fingerprint, setFingerprint] = useState('');
  const ephemeralPrivateKeyRef = useRef(null);
  const loadedKeysRef = useRef(null);
  
  const addLog = useCallback((message, type = 'info') => {
    setLogs(prev => [...prev, {
      message,
      type,
      time: new Date().toLocaleTimeString()
    }]);
  }, []);
  
  // Initiate key exchange - simplified, no password prompt
  const initiateKeyExchange = async () => {
    const keysToUse = privateKeys || loadedKeysRef.current;
    
    if (!keysToUse) {
      setError('❌ Private keys not available. Please log in again.');
      return;
    }
    
    if (!socket) {
      setError('Socket not connected');
      return;
    }
    
    // Proceed with key exchange
    await proceedWithKeyExchange(keysToUse);
  };
  
  // Separate function to actually proceed with the exchange
  const proceedWithKeyExchange = async (keysToUse) => {
    if (!keysToUse) {
      setError('No keys available');
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
      console.log('Exporting ephemeral public key...');
      const ephPubJwk = window.CryptoLib.cleanJwkPublic(
        await crypto.subtle.exportKey('jwk', ephKp.publicKey)
      );
      
      console.log('Exporting signing public key...');
      const sigPubJwk = window.CryptoLib.cleanJwkPublic(
        await crypto.subtle.exportKey('jwk', keysToUse.signing)
      );
      
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
      console.error('Proceed error:', e);
      setError(e.message);
      setStatus('error');
      addLog(e.message, 'error');
    }
  };
  
  // Initialize socket
  useEffect(() => {
    if (!token) return;
    
    const s = io(API_URL, { auth: { token } });
    
    s.on('connect', () => console.log('Socket connected'));
    s.on('connect_error', (e) => {
      console.error('Socket error:', e);
      setError('Connection error');
    });
    
    setSocket(s);
    return () => s.disconnect();
  }, [token]);
  
  // Load partner's keys
  useEffect(() => {
    if (!partnerId || !token) {
      console.log('Waiting for prerequisites:', { partnerId, token: !!token });
      return;
    }
    
    const loadPartner = async () => {
      try {
        console.log('Loading partner bundle for:', partnerId);
        const res = await fetch(`${API_URL}/api/keys/bundle/${partnerId}`, {
          headers: { Authorization: `Bearer ${token}` }
        });
        
        console.log('Partner bundle response:', res.status, res.statusText);
        
        if (!res.ok) {
          const errData = await res.json();
          throw new Error(errData.error || 'Failed to load partner');
        }
        
        const data = await res.json();
        console.log('Partner data loaded:', data.username);
        setPartner(data);
        
        // Import partner's identity key for verification
        try {
          console.log('Importing identity key...');
          const publicKeyString = data.publicKeys.identityKey.publicKey;
          console.log('Public key string type:', typeof publicKeyString);
          const idJwk = JSON.parse(publicKeyString);
          console.log('JWK parsed:', { kty: idJwk.kty, crv: idJwk.crv, x: idJwk.x ? 'present' : 'missing', y: idJwk.y ? 'present' : 'missing' });
          const idKey = await crypto.subtle.importKey(
            'jwk', idJwk,
            { name: 'ECDSA', namedCurve: 'P-256' },
            true, ['verify']
          );
          console.log('Key imported successfully');
          setPartnerIdentityKey(idKey);
          
          setStatus('ready');
          addLog(`Loaded ${data.username}'s public keys`, 'success');
        } catch (keyError) {
          console.error('Key import error:', keyError);
          console.error('Error stack:', keyError.stack);
          throw keyError;
        }
        
      } catch (e) {
        console.error('Partner load error:', e);
        setError(e.message);
        setStatus('error');
        addLog(e.message, 'error');
      }
    };
    
    loadPartner();
  }, [partnerId, token, addLog]);
  
  // Socket event handlers
  useEffect(() => {
    if (!socket || !partnerIdentityKey || !privateKeys) return;
    
    // Handle incoming key exchange request (we're the responder)
    socket.on('keyexchange:request', async (data) => {
      if (data.initiatorId === partnerId) {
        addLog('Received key exchange request', 'info');
        setStatus('responding');
        await respondToKeyExchange(data);
      }
    });
    
    // Handle response (we're the initiator)
    socket.on('keyexchange:response', async (data) => {
      if (data.responderId === partnerId) {
        addLog('Received key exchange response', 'info');
        await completeKeyExchange(data);
      }
    });
    
    // Handle confirmation
    socket.on('keyexchange:confirmed', (data) => {
      if (data.partnerId === partnerId) {
        addLog('Key exchange confirmed!', 'success');
        finalizeKeyExchange();
      }
    });
    
    socket.on('keyexchange:offline', () => {
      setError('Partner is offline');
      setStatus('error');
      addLog('Partner is offline', 'error');
    });
    
    return () => {
      socket.off('keyexchange:request');
      socket.off('keyexchange:response');
      socket.off('keyexchange:confirmed');
      socket.off('keyexchange:offline');
    };
  }, [socket, partnerId, partnerIdentityKey, privateKeys]);
  
  // Respond to key exchange
  const respondToKeyExchange = async (data) => {
    try {
      // Get the signing key - if not in state, check if it's loaded
      const signingKey = privateKeys?.signing || loadedKeysRef.current?.signing;
      if (!signingKey) {
        throw new Error('Private signing key not available');
      }
      
      addLog('Verifying initiator signature...', 'info');
      
      const bundle = data.bundle;
      
      // Parse keys
      const theirEphJwk = JSON.parse(bundle.ephemeralKey);
      const theirIdJwk = JSON.parse(bundle.identityKey);
      
      // Verify timestamp
      if (Math.abs(Date.now() - bundle.timestamp) > 5 * 60 * 1000) {
        throw new Error('Timestamp expired - possible replay attack');
      }
      
      // Verify signature
      const msgToVerify = JSON.stringify({
        ephemeralKey: bundle.ephemeralKey,
        identityKey: bundle.identityKey,
        timestamp: bundle.timestamp
      });
      
      const valid = await crypto.subtle.verify(
        { name: 'ECDSA', hash: 'SHA-256' },
        partnerIdentityKey,
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
      const mySigPubJwk = window.CryptoLib.cleanJwkPublic(
        await crypto.subtle.exportKey('jwk', signingKey)
      );
      
      const respTimestamp = Date.now();
      const respBundle = {
        ephemeralKey: JSON.stringify(myEphPubJwk),
        identityKey: JSON.stringify(mySigPubJwk),
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
      
      socket.emit('keyexchange:respond', {
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
  };
  
  // Complete key exchange (initiator side)
  const completeKeyExchange = async (data) => {
    try {
      setStatus('deriving');
      addLog('Verifying responder signature...', 'info');
      
      const bundle = data.bundle;
      
      // Parse keys
      const theirEphJwk = window.CryptoLib.cleanJwk(JSON.parse(bundle.ephemeralKey));
      
      // Verify timestamp
      if (Math.abs(Date.now() - bundle.timestamp) > 5 * 60 * 1000) {
        throw new Error('Timestamp expired');
      }
      
      // Verify signature
      const msgToVerify = JSON.stringify({
        ephemeralKey: bundle.ephemeralKey,
        identityKey: bundle.identityKey,
        salt: bundle.salt,
        timestamp: bundle.timestamp
      });
      
      const valid = await crypto.subtle.verify(
        { name: 'ECDSA', hash: 'SHA-256' },
        partnerIdentityKey,
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
      
      socket.emit('keyexchange:confirm', {
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
  };
  
  // Finalize (responder side after confirmation)
  const finalizeKeyExchange = async () => {
    if (!sessionKey) return;
    
    try {
      await window.CryptoLib.storeSessionKey(partnerId, sessionKey);
      
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
          {status === 'ready' && '✅ Ready to exchange keys'}
          {status === 'initiating' && '🔄 Initiating...'}
          {status === 'responding' && '🔄 Responding...'}
          {status === 'deriving' && '🔄 Deriving keys...'}
          {status === 'confirming' && '🔄 Confirming...'}
          {status === 'complete' && '✅ Key exchange complete!'}
          {status === 'error' && '❌ Key exchange failed'}
        </div>
        
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
          {status === 'ready' && (
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
