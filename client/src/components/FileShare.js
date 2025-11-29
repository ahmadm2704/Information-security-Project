import React, { useState, useEffect } from 'react';
import { useAuth, API_URL } from '../App';

function FileShare() {
  const { token } = useAuth();
  const [files, setFiles] = useState([]);
  const [uploading, setUploading] = useState(false);
  const [uploadProgress, setUploadProgress] = useState(0);
  const [error, setError] = useState('');
  
  // Load files
  useEffect(() => {
    if (!token) return;
    
    fetch(`${API_URL}/api/files/my-files`, {
      headers: { Authorization: `Bearer ${token}` }
    })
      .then(r => r.json())
      .then(data => setFiles(data.files || []))
      .catch(console.error);
  }, [token]);
  
  const handleUpload = async (e) => {
    const file = e.target.files?.[0];
    if (!file) return;
    
    // Check if we have a master key (for demo, we'll create one)
    let masterKey = sessionStorage.getItem('masterKey');
    if (!masterKey) {
      const key = await crypto.subtle.generateKey(
        { name: 'AES-GCM', length: 256 },
        true, ['encrypt', 'decrypt']
      );
      const jwk = await crypto.subtle.exportKey('jwk', key);
      masterKey = JSON.stringify(jwk);
      sessionStorage.setItem('masterKey', masterKey);
    }
    
    const jwk = JSON.parse(masterKey);
    delete jwk.key_ops;
    delete jwk.ext;
    const sessionKey = await crypto.subtle.importKey(
      'jwk', jwk,
      { name: 'AES-GCM', length: 256 },
      true, ['encrypt', 'decrypt']
    );
    
    setUploading(true);
    setUploadProgress(0);
    setError('');
    
    try {
      // Encrypt file
      setUploadProgress(20);
      const encrypted = await window.CryptoLib.encryptFile(sessionKey, file);
      
      setUploadProgress(50);
      
      // Create form data
      const formData = new FormData();
      formData.append('encryptedMetadata', JSON.stringify(encrypted.encryptedMetadata));
      formData.append('encryption', JSON.stringify(encrypted.encryption));
      formData.append('originalSize', encrypted.originalSize);
      formData.append('totalChunks', '1');
      formData.append('hash', encrypted.hash);
      
      // Create blob from encrypted data
      const encryptedBlob = new Blob([
        window.CryptoLib.fromBase64(encrypted.encryptedData.data)
      ]);
      formData.append('file', encryptedBlob, 'encrypted');
      
      setUploadProgress(70);
      
      // Upload
      const res = await fetch(`${API_URL}/api/files/upload`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}` },
        body: formData
      });
      
      if (!res.ok) throw new Error('Upload failed');
      
      setUploadProgress(100);
      
      // Refresh file list
      const filesRes = await fetch(`${API_URL}/api/files/my-files`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      const filesData = await filesRes.json();
      setFiles(filesData.files || []);
      
    } catch (err) {
      console.error('Upload error:', err);
      setError(err.message);
    }
    
    setUploading(false);
  };
  
  const formatSize = (bytes) => {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
    return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
  };
  
  return (
    <div className="file-share-container">
      <div className="file-share-header">
        <h1>📁 Encrypted File Storage</h1>
        <p>Files are encrypted client-side before upload</p>
      </div>
      
      {/* Upload Area */}
      <div className="upload-area">
        <label className="upload-label">
          <input
            type="file"
            onChange={handleUpload}
            disabled={uploading}
            style={{ display: 'none' }}
          />
          <div className="upload-content">
            {uploading ? (
              <>
                <div className="upload-progress">
                  <div className="progress-bar" style={{ width: `${uploadProgress}%` }} />
                </div>
                <p>Encrypting and uploading... {uploadProgress}%</p>
              </>
            ) : (
              <>
                <span className="upload-icon">📤</span>
                <p>Click to select a file to encrypt and upload</p>
                <p className="upload-hint">Max file size: 100MB</p>
              </>
            )}
          </div>
        </label>
      </div>
      
      {error && <div className="error-message">{error}</div>}
      
      {/* File List */}
      <div className="file-list">
        <h2>Your Encrypted Files</h2>
        
        {files.length === 0 ? (
          <div className="empty-state">
            <p>No files uploaded yet</p>
          </div>
        ) : (
          <div className="files-grid">
            {files.map(file => (
              <div key={file._id} className="file-card">
                <div className="file-icon">🔒</div>
                <div className="file-info">
                  <span className="file-name">Encrypted File</span>
                  <span className="file-size">{formatSize(file.originalSize)}</span>
                  <span className="file-date">
                    {new Date(file.createdAt).toLocaleDateString()}
                  </span>
                </div>
                <div className="file-actions">
                  <button className="btn btn-small">Download</button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
      
      {/* Security Info */}
      <div className="security-info">
        <h3>🔐 Encryption Details</h3>
        <ul>
          <li><strong>Algorithm:</strong> AES-256-GCM</li>
          <li><strong>Key Derivation:</strong> HKDF-SHA256</li>
          <li><strong>Integrity:</strong> SHA-256 hash verification</li>
          <li><strong>Client-side:</strong> Files encrypted before upload</li>
        </ul>
      </div>
    </div>
  );
}

export default FileShare;
