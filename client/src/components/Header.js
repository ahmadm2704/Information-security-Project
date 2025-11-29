import React from 'react';
import { Link, useLocation, useNavigate } from 'react-router-dom';
import { useAuth } from '../App';

function Header() {
  const { user, logout, isAuthenticated } = useAuth();
  const location = useLocation();
  const navigate = useNavigate();
  
  // Hide on auth pages
  if (['/login', '/register'].includes(location.pathname)) {
    return null;
  }
  
  const handleLogout = () => {
    logout();
    navigate('/login');
  };
  
  return (
    <header className="header">
      <div className="header-left">
        <Link to="/" className="logo">
          <span className="logo-icon">🔐</span>
          <span className="logo-text">SecureComm</span>
        </Link>
        
        {isAuthenticated && (
          <nav className="nav">
            <Link to="/" className={location.pathname === '/' || location.pathname.startsWith('/chat') ? 'active' : ''}>
              💬 Messages
            </Link>
            <Link to="/files" className={location.pathname === '/files' ? 'active' : ''}>
              📁 Files
            </Link>
            <Link to="/security" className={location.pathname === '/security' ? 'active' : ''}>
              🛡️ Security
            </Link>
          </nav>
        )}
      </div>
      
      {isAuthenticated && (
        <div className="header-right">
          <span className="encryption-badge">🔒 E2E Encrypted</span>
          <div className="user-menu">
            <span className="avatar">{user?.username?.[0]?.toUpperCase()}</span>
            <span className="username">{user?.username}</span>
            <button onClick={handleLogout} className="logout-btn">Logout</button>
          </div>
        </div>
      )}
    </header>
  );
}

export default Header;
