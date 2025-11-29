import React, { useState, useEffect } from 'react';
import { useAuth, API_URL } from '../App';

function SecurityLogs() {
  const { token } = useAuth();
  const [logs, setLogs] = useState([]);
  const [summary, setSummary] = useState(null);
  const [filter, setFilter] = useState('all');
  const [loading, setLoading] = useState(true);
  
  useEffect(() => {
    if (!token) return;
    
    // Load logs
    fetch(`${API_URL}/api/logs?limit=100`, {
      headers: { Authorization: `Bearer ${token}` }
    })
      .then(r => r.json())
      .then(data => {
        setLogs(data.logs || []);
        setLoading(false);
      })
      .catch(err => {
        console.error(err);
        setLoading(false);
      });
    
    // Load summary
    fetch(`${API_URL}/api/logs/summary`, {
      headers: { Authorization: `Bearer ${token}` }
    })
      .then(r => r.json())
      .then(data => setSummary(data))
      .catch(console.error);
      
  }, [token]);
  
  const getEventIcon = (type) => {
    const icons = {
      'AUTH_LOGIN_SUCCESS': '✅',
      'AUTH_LOGIN_FAILED': '❌',
      'AUTH_REGISTER': '👤',
      'AUTH_LOGOUT': '👋',
      'KEY_PAIR_GENERATED': '🔑',
      'KEY_EXCHANGE_INITIATED': '🔄',
      'KEY_EXCHANGE_COMPLETED': '🔐',
      'KEY_EXCHANGE_FAILED': '⚠️',
      'MESSAGE_SENT': '📨',
      'REPLAY_ATTACK_DETECTED': '🚨',
      'INVALID_SIGNATURE_DETECTED': '🚨',
      'FILE_UPLOADED': '📤',
      'FILE_DOWNLOADED': '📥'
    };
    return icons[type] || '📝';
  };
  
  const getSeverityClass = (severity) => {
    return `severity-${severity.toLowerCase()}`;
  };
  
  const filteredLogs = filter === 'all' 
    ? logs 
    : logs.filter(log => {
        if (filter === 'critical') return log.severity === 'CRITICAL' || log.severity === 'ERROR';
        if (filter === 'auth') return log.eventType.startsWith('AUTH_');
        if (filter === 'keys') return log.eventType.includes('KEY');
        if (filter === 'attacks') return log.eventType.includes('ATTACK') || log.eventType.includes('INVALID');
        return true;
      });
  
  return (
    <div className="security-logs-container">
      <div className="security-header">
        <h1>🛡️ Security Logs</h1>
        <p>Monitor your account security events</p>
      </div>
      
      {/* Summary Cards */}
      {summary && (
        <div className="summary-cards">
          <div className="summary-card">
            <span className="card-icon">📊</span>
            <div className="card-content">
              <span className="card-value">{logs.length}</span>
              <span className="card-label">Total Events</span>
            </div>
          </div>
          
          <div className="summary-card critical">
            <span className="card-icon">🚨</span>
            <div className="card-content">
              <span className="card-value">{summary.criticalAlerts || 0}</span>
              <span className="card-label">Critical Alerts</span>
            </div>
          </div>
          
          <div className="summary-card success">
            <span className="card-icon">✅</span>
            <div className="card-content">
              <span className="card-value">
                {logs.filter(l => l.eventType === 'AUTH_LOGIN_SUCCESS').length}
              </span>
              <span className="card-label">Successful Logins</span>
            </div>
          </div>
          
          <div className="summary-card warning">
            <span className="card-icon">🔑</span>
            <div className="card-content">
              <span className="card-value">
                {logs.filter(l => l.eventType === 'KEY_EXCHANGE_COMPLETED').length}
              </span>
              <span className="card-label">Key Exchanges</span>
            </div>
          </div>
        </div>
      )}
      
      {/* Filters */}
      <div className="log-filters">
        <button 
          className={filter === 'all' ? 'active' : ''} 
          onClick={() => setFilter('all')}
        >
          All Events
        </button>
        <button 
          className={filter === 'critical' ? 'active' : ''} 
          onClick={() => setFilter('critical')}
        >
          Critical
        </button>
        <button 
          className={filter === 'auth' ? 'active' : ''} 
          onClick={() => setFilter('auth')}
        >
          Authentication
        </button>
        <button 
          className={filter === 'keys' ? 'active' : ''} 
          onClick={() => setFilter('keys')}
        >
          Key Operations
        </button>
        <button 
          className={filter === 'attacks' ? 'active' : ''} 
          onClick={() => setFilter('attacks')}
        >
          Attack Detection
        </button>
      </div>
      
      {/* Logs List */}
      <div className="logs-list">
        {loading ? (
          <div className="loading">Loading logs...</div>
        ) : filteredLogs.length === 0 ? (
          <div className="empty-state">No security logs found</div>
        ) : (
          filteredLogs.map((log, idx) => (
            <div key={idx} className={`log-item ${getSeverityClass(log.severity)}`}>
              <div className="log-icon">{getEventIcon(log.eventType)}</div>
              <div className="log-content">
                <div className="log-header">
                  <span className="log-type">{log.eventType.replace(/_/g, ' ')}</span>
                  <span className={`log-severity ${getSeverityClass(log.severity)}`}>
                    {log.severity}
                  </span>
                  <span className={`log-result ${log.result?.toLowerCase()}`}>
                    {log.result}
                  </span>
                </div>
                <div className="log-details">
                  {log.details && Object.keys(log.details).length > 0 && (
                    <span className="log-detail">
                      {JSON.stringify(log.details)}
                    </span>
                  )}
                </div>
                <div className="log-meta">
                  <span className="log-time">
                    {new Date(log.timestamp).toLocaleString()}
                  </span>
                  {log.request?.ip && (
                    <span className="log-ip">IP: {log.request.ip}</span>
                  )}
                </div>
              </div>
            </div>
          ))
        )}
      </div>
      
      {/* Security Tips */}
      <div className="security-tips">
        <h3>🔒 Security Tips</h3>
        <ul>
          <li>Review your login history regularly</li>
          <li>Complete key exchange before sending sensitive messages</li>
          <li>Verify key fingerprints with your contacts</li>
          <li>Report any suspicious activity immediately</li>
        </ul>
      </div>
    </div>
  );
}

export default SecurityLogs;
