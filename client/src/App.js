/**
 * SecureComm Main Application
 */

import React, { useState, useEffect, createContext, useContext } from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import './crypto/cryptoLib';

// Components
import Header from './components/Header';
import Login from './components/Login';
import Register from './components/Register';
import Chat from './components/Chat';
import KeyExchange from './components/KeyExchange';
import FileShare from './components/FileShare';
import SecurityLogs from './components/SecurityLogs';

import './styles/index.css';

const API_URL = process.env.REACT_APP_API_URL || 'http://localhost:5000';

// ==========================================
// AUTH CONTEXT
// ==========================================

const AuthContext = createContext(null);

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within AuthProvider');
  }
  return context;
};

function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [token, setToken] = useState(null);
  const [privateKeys, setPrivateKeys] = useState(null);
  const [loading, setLoading] = useState(true);

  // Check existing session
  useEffect(() => {
    const init = async () => {
      const storedToken = localStorage.getItem('token');
      const storedUser = localStorage.getItem('user');
      
      if (storedToken && storedUser) {
        try {
          const res = await fetch(`${API_URL}/api/auth/verify`, {
            headers: { Authorization: `Bearer ${storedToken}` }
          });
          
          if (res.ok) {
            setToken(storedToken);
            setUser(JSON.parse(storedUser));
          } else {
            localStorage.removeItem('token');
            localStorage.removeItem('user');
          }
        } catch (e) {
          console.error('Session check failed:', e);
        }
      }
      setLoading(false);
    };
    
    init();
  }, []);

  const login = async (username, password) => {
    const res = await fetch(`${API_URL}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password })
    });
    
    const data = await res.json();
    if (!res.ok) throw new Error(data.error);
    
    console.log('[APP] Login response user.id:', data.user.id);
    
    localStorage.setItem('token', data.token);
    localStorage.setItem('user', JSON.stringify(data.user));
    setToken(data.token);
    setUser(data.user);
    
    // Generate new keys during login (ephemeral for this session)
    // This ensures keys are available for key exchange
    try {
      console.log('[APP] Generating keys for this session...');
      const keySet = await window.CryptoLib.generateUserKeys();
      
      // Store keys in sessionStorage with password encryption
      console.log('[APP] Storing keys with password...');
      await window.CryptoLib.storePrivateKeys(data.user.id, keySet.privateKeys, password);
      
      setPrivateKeys(keySet.privateKeys);
      console.log('✅ Keys generated and stored successfully');
    } catch (e) {
      console.error('❌ Failed to generate/store keys:', e.message);
      console.warn('Continuing without stored keys - user can enter password on key exchange page');
    }
    
    return data;
  };

  const register = async (username, email, password) => {
    // Generate keys
    console.log('🔑 Generating encryption keys...');
    const keySet = await window.CryptoLib.generateUserKeys();
    
    // Register with server
    const res = await fetch(`${API_URL}/api/auth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, email, password, publicKeys: keySet.publicKeys })
    });
    
    const data = await res.json();
    if (!res.ok) throw new Error(data.error);
    
    console.log('[APP] Register response user.id:', data.user.id, 'type:', typeof data.user.id);
    
    // Store private keys
    console.log('[APP] Storing keys with userId:', data.user.id);
    try {
      await window.CryptoLib.storePrivateKeys(data.user.id, keySet.privateKeys, password);
      console.log('✅ Private keys stored successfully in IndexedDB');
    } catch (storeErr) {
      console.error('❌ Failed to store private keys in IndexedDB:', storeErr);
      console.error('This is a non-fatal error - user can still login but will need password on page reload');
    }
    
    localStorage.setItem('token', data.token);
    localStorage.setItem('user', JSON.stringify(data.user));
    setToken(data.token);
    setUser(data.user);
    setPrivateKeys(keySet.privateKeys);
    
    return data;
  };

  const logout = () => {
    fetch(`${API_URL}/api/auth/logout`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}` }
    }).catch(() => {});
    
    localStorage.removeItem('token');
    localStorage.removeItem('user');
    sessionStorage.clear();
    setToken(null);
    setUser(null);
    setPrivateKeys(null);
  };

  return (
    <AuthContext.Provider value={{
      user,
      token,
      privateKeys,
      setPrivateKeys,
      loading,
      login,
      register,
      logout,
      isAuthenticated: !!token
    }}>
      {children}
    </AuthContext.Provider>
  );
}

// ==========================================
// PROTECTED ROUTE
// ==========================================

function ProtectedRoute({ children }) {
  const { isAuthenticated, loading } = useAuth();
  
  if (loading) {
    return (
      <div className="loading-screen">
        <div className="spinner"></div>
        <p>Loading...</p>
      </div>
    );
  }
  
  if (!isAuthenticated) {
    return <Navigate to="/login" replace />;
  }
  
  return children;
}

// ==========================================
// MAIN APP
// ==========================================

function App() {
  return (
    <AuthProvider>
      <BrowserRouter>
        <div className="app">
          <Header />
          <main className="main-content">
            <Routes>
              <Route path="/login" element={<Login />} />
              <Route path="/register" element={<Register />} />
              <Route path="/" element={<ProtectedRoute><Chat /></ProtectedRoute>} />
              <Route path="/chat/:partnerId?" element={<ProtectedRoute><Chat /></ProtectedRoute>} />
              <Route path="/key-exchange/:partnerId" element={<ProtectedRoute><KeyExchange /></ProtectedRoute>} />
              <Route path="/files" element={<ProtectedRoute><FileShare /></ProtectedRoute>} />
              <Route path="/security" element={<ProtectedRoute><SecurityLogs /></ProtectedRoute>} />
              <Route path="*" element={<Navigate to="/" replace />} />
            </Routes>
          </main>
        </div>
      </BrowserRouter>
    </AuthProvider>
  );
}

export default App;
export { API_URL };
