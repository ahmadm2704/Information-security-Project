import React, { useState, useEffect, useRef, useCallback } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { io } from 'socket.io-client';
import { useAuth, API_URL } from '../App';

function Chat() {
  const { partnerId } = useParams();
  const navigate = useNavigate();
  const { user, token, privateKeys } = useAuth();
  
  const [socket, setSocket] = useState(null);
  const [conversations, setConversations] = useState([]);
  const [searchQuery, setSearchQuery] = useState('');
  const [searchResults, setSearchResults] = useState([]);
  const [partner, setPartner] = useState(null);
  const [messages, setMessages] = useState([]);
  const [newMessage, setNewMessage] = useState('');
  const [sessionKey, setSessionKey] = useState(null);
  const [isTyping, setIsTyping] = useState(false);
  const [onlineUsers, setOnlineUsers] = useState([]);
  
  const messagesEndRef = useRef(null);
  const typingTimeoutRef = useRef(null);
  
  // Auto scroll to bottom
  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };
  
  useEffect(scrollToBottom, [messages]);
  
  // Initialize socket
  useEffect(() => {
    if (!token) return;
    
    const newSocket = io(API_URL, {
      auth: { token },
      transports: ['websocket', 'polling']
    });
    
    newSocket.on('connect', () => {
      console.log('✅ Socket connected');
    });
    
    newSocket.on('connect_error', (err) => {
      console.error('❌ Socket error:', err.message);
    });
    
    newSocket.on('users:online', (users) => {
      setOnlineUsers(users);
    });
    
    newSocket.on('user:online', ({ userId }) => {
      setOnlineUsers(prev => [...new Set([...prev, userId])]);
    });
    
    newSocket.on('user:offline', ({ userId }) => {
      setOnlineUsers(prev => prev.filter(id => id !== userId));
    });
    
    setSocket(newSocket);
    
    return () => newSocket.disconnect();
  }, [token]);
  
  // Handle incoming messages
  useEffect(() => {
    if (!socket) return;
    
    const handleMessage = async (data) => {
      if (data.senderId === partnerId) {
        // Try to decrypt
        let content = '[Encrypted]';
        if (sessionKey) {
          try {
            const decrypted = await window.CryptoLib.decryptMessage(sessionKey, {
              encryptedPayload: data.encryptedPayload,
              iv: data.iv
            });
            content = decrypted.content;
          } catch (e) {
            console.error('Decrypt error:', e);
          }
        }
        
        setMessages(prev => [...prev, {
          ...data,
          content,
          isMine: false
        }]);
      }
    };
    
    const handleTypingStart = ({ userId }) => {
      if (userId === partnerId) setIsTyping(true);
    };
    
    const handleTypingStop = ({ userId }) => {
      if (userId === partnerId) setIsTyping(false);
    };
    
    socket.on('message:receive', handleMessage);
    socket.on('typing:start', handleTypingStart);
    socket.on('typing:stop', handleTypingStop);
    
    return () => {
      socket.off('message:receive', handleMessage);
      socket.off('typing:start', handleTypingStart);
      socket.off('typing:stop', handleTypingStop);
    };
  }, [socket, partnerId, sessionKey]);
  
  // Load conversations
  useEffect(() => {
    if (!token) return;
    
    fetch(`${API_URL}/api/messages/conversations`, {
      headers: { Authorization: `Bearer ${token}` }
    })
      .then(r => r.json())
      .then(data => setConversations(data.conversations || []))
      .catch(console.error);
  }, [token]);
  
  // Load partner and messages
  useEffect(() => {
    if (!partnerId || !token) {
      setPartner(null);
      setMessages([]);
      return;
    }
    
    // Load partner info
    fetch(`${API_URL}/api/keys/bundle/${partnerId}`, {
      headers: { Authorization: `Bearer ${token}` }
    })
      .then(r => r.json())
      .then(data => setPartner(data))
      .catch(console.error);
    
    // Load messages
    fetch(`${API_URL}/api/messages/${partnerId}`, {
      headers: { Authorization: `Bearer ${token}` }
    })
      .then(r => r.json())
      .then(data => {
        setMessages((data.messages || []).map(m => ({
          ...m,
          isMine: m.senderId === user.id,
          content: '[Encrypted]'
        })));
      })
      .catch(console.error);
    
    // Check for session key
    window.CryptoLib.retrieveSessionKey(partnerId)
      .then(key => {
        if (key) {
          setSessionKey(key);
          console.log('✅ Session key loaded');
        } else {
          setSessionKey(null);
        }
      })
      .catch(() => setSessionKey(null));
      
  }, [partnerId, token, user]);
  
  // Search users
  useEffect(() => {
    if (!searchQuery || searchQuery.length < 1) {
      setSearchResults([]);
      return;
    }
    
    const timeout = setTimeout(() => {
      fetch(`${API_URL}/api/auth/users/search?q=${encodeURIComponent(searchQuery)}`, {
        headers: { Authorization: `Bearer ${token}` }
      })
        .then(r => r.json())
        .then(data => setSearchResults(data.users || []))
        .catch(console.error);
    }, 300);
    
    return () => clearTimeout(timeout);
  }, [searchQuery, token]);
  
  // Send message
  const sendMessage = async () => {
    if (!newMessage.trim() || !socket || !partnerId) return;
    
    if (!sessionKey) {
      alert('Please complete key exchange first');
      return;
    }
    
    try {
      const encrypted = await window.CryptoLib.encryptMessage(sessionKey, newMessage);
      
      const msgData = {
        recipientId: partnerId,
        encryptedPayload: encrypted.encryptedPayload,
        iv: encrypted.iv,
        nonce: encrypted.nonce,
        timestamp: encrypted.timestamp,
        sequenceNumber: messages.length + 1
      };
      
      socket.emit('message:send', msgData);
      
      setMessages(prev => [...prev, {
        ...msgData,
        senderId: user.id,
        content: newMessage,
        isMine: true
      }]);
      
      setNewMessage('');
      
      // Stop typing indicator
      socket.emit('typing:stop', { recipientId: partnerId });
      
    } catch (err) {
      console.error('Send error:', err);
      alert('Failed to send message');
    }
  };
  
  // Handle typing
  const handleTyping = (e) => {
    setNewMessage(e.target.value);
    
    if (socket && partnerId) {
      socket.emit('typing:start', { recipientId: partnerId });
      
      clearTimeout(typingTimeoutRef.current);
      typingTimeoutRef.current = setTimeout(() => {
        socket.emit('typing:stop', { recipientId: partnerId });
      }, 2000);
    }
  };
  
  const isOnline = (userId) => onlineUsers.includes(userId);
  
  return (
    <div className="chat-container">
      {/* Sidebar */}
      <div className="sidebar">
        <div className="sidebar-header">
          <h2>💬 Chats</h2>
          <input
            type="text"
            placeholder="Search users..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="search-input"
          />
        </div>
        
        {/* Search Results */}
        {searchResults.length > 0 && (
          <div className="search-results">
            <div className="section-title">Search Results</div>
            {searchResults.map(u => (
              <div
                key={u.id}
                className="conversation-item"
                onClick={() => {
                  navigate(`/chat/${u.id}`);
                  setSearchQuery('');
                  setSearchResults([]);
                }}
              >
                <div className="avatar">{u.username[0].toUpperCase()}</div>
                <div className="info">
                  <span className="name">{u.username}</span>
                </div>
              </div>
            ))}
          </div>
        )}
        
        {/* Conversations */}
        <div className="conversations">
          {conversations.map(c => (
            <div
              key={c.partnerId}
              className={`conversation-item ${partnerId === c.partnerId ? 'active' : ''}`}
              onClick={() => navigate(`/chat/${c.partnerId}`)}
            >
              <div className={`avatar ${isOnline(c.partnerId) ? 'online' : ''}`}>
                {c.partnerUsername[0].toUpperCase()}
              </div>
              <div className="info">
                <span className="name">{c.partnerUsername}</span>
                {c.unreadCount > 0 && (
                  <span className="unread">{c.unreadCount}</span>
                )}
              </div>
            </div>
          ))}
          
          {conversations.length === 0 && !searchQuery && (
            <div className="empty-state">
              <p>No conversations yet</p>
              <p>Search for a user to start chatting</p>
            </div>
          )}
        </div>
      </div>
      
      {/* Main Chat Area */}
      <div className="chat-main">
        {partner ? (
          <>
            {/* Chat Header */}
            <div className="chat-header">
              <div className="partner-info">
                <div className={`avatar ${isOnline(partnerId) ? 'online' : ''}`}>
                  {partner.username?.[0]?.toUpperCase()}
                </div>
                <div className="details">
                  <span className="name">{partner.username}</span>
                  <span className="status">
                    {isOnline(partnerId) ? '🟢 Online' : '⚪ Offline'}
                  </span>
                </div>
              </div>
              
              <div className="chat-actions">
                {sessionKey ? (
                  <span className="encrypted-badge">🔐 Encrypted</span>
                ) : (
                  <button
                    className="btn btn-warning"
                    onClick={() => navigate(`/key-exchange/${partnerId}`)}
                  >
                    🔑 Start Key Exchange
                  </button>
                )}
              </div>
            </div>
            
            {/* Messages */}
            <div className="messages-container">
              {!sessionKey && (
                <div className="key-exchange-notice">
                  <p>🔐 Complete key exchange to send encrypted messages</p>
                  <button
                    className="btn btn-primary"
                    onClick={() => navigate(`/key-exchange/${partnerId}`)}
                  >
                    Start Key Exchange
                  </button>
                </div>
              )}
              
              <div className="messages">
                {messages.map((msg, idx) => (
                  <div
                    key={idx}
                    className={`message ${msg.isMine ? 'mine' : 'theirs'}`}
                  >
                    <div className="message-content">{msg.content}</div>
                    <div className="message-time">
                      {new Date(msg.timestamp || msg.createdAt).toLocaleTimeString([], {
                        hour: '2-digit',
                        minute: '2-digit'
                      })}
                    </div>
                  </div>
                ))}
                
                {isTyping && (
                  <div className="typing-indicator">
                    <span>{partner.username} is typing...</span>
                  </div>
                )}
                
                <div ref={messagesEndRef} />
              </div>
            </div>
            
            {/* Message Input */}
            <div className="message-input-container">
              <input
                type="text"
                placeholder={sessionKey ? "Type a message..." : "Complete key exchange first..."}
                value={newMessage}
                onChange={handleTyping}
                onKeyPress={(e) => e.key === 'Enter' && sendMessage()}
                disabled={!sessionKey}
                className="message-input"
              />
              <button
                onClick={sendMessage}
                disabled={!sessionKey || !newMessage.trim()}
                className="btn btn-primary send-btn"
              >
                Send
              </button>
            </div>
          </>
        ) : (
          <div className="no-chat-selected">
            <div className="welcome">
              <h2>👋 Welcome to SecureComm</h2>
              <p>Select a conversation or search for a user to start chatting</p>
              <div className="features">
                <div className="feature">
                  <span>🔐</span>
                  <p>End-to-end encrypted</p>
                </div>
                <div className="feature">
                  <span>🔑</span>
                  <p>Custom key exchange</p>
                </div>
                <div className="feature">
                  <span>🛡️</span>
                  <p>MITM protection</p>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

export default Chat;
