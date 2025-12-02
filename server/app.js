require('dotenv').config();

const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const mongoose = require('mongoose');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const jwt = require('jsonwebtoken');
const path = require('path');

// Models
const User = require('./models/User');
const Message = require('./models/Message');
const SecurityLog = require('./models/SecurityLog');
const EncryptedFile = require('./models/EncryptedFile');

// Routes
const authRoutes = require('./routes/auth');
const keysRoutes = require('./routes/keys');
const messagesRoutes = require('./routes/messages');
const filesRoutes = require('./routes/files');
const logsRoutes = require('./routes/logs');

// Config
const JWT_SECRET = process.env.JWT_SECRET || 'securecomm-super-secret-jwt-key-2024-change-in-production';
const PORT = process.env.PORT || 5000;
const CLIENT_URL = process.env.CLIENT_URL || 'http://localhost:3000';
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/securecomm';

const app = express();
const server = http.createServer(app);

// Socket.io
const io = new Server(server, {
  cors: {
    origin: CLIENT_URL,
    methods: ['GET', 'POST'],
    credentials: true
  },
  maxHttpBufferSize: 50 * 1024 * 1024  // 50MB for file transfers
});

// Security middleware
app.use(helmet({ contentSecurityPolicy: false }));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: { error: 'Too many requests' }
});

const authLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 20,
  message: { error: 'Too many auth attempts' }
});

app.use(limiter);
app.use('/api/auth/login', authLimiter);
app.use('/api/auth/register', authLimiter);

// CORS
app.use(cors({
  origin: CLIENT_URL,
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

// Body parsing
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// Static files
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Routes
app.use('/api/auth', authRoutes);
app.use('/api/keys', keysRoutes);
app.use('/api/messages', messagesRoutes);
app.use('/api/files', filesRoutes);
app.use('/api/logs', logsRoutes);

// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'healthy', timestamp: new Date().toISOString() });
});

// ==========================================
// SOCKET.IO HANDLING
// ==========================================

const connectedUsers = new Map();

// Socket authentication
io.use((socket, next) => {
  const token = socket.handshake.auth.token;
  
  if (!token) {
    console.log('[SOCKET] ❌ No token provided');
    return next(new Error('Authentication required'));
  }
  
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    socket.userId = decoded.userId;
    socket.username = decoded.username;
    console.log(`[SOCKET] ✅ Authenticated: ${decoded.username}`);
    next();
  } catch (err) {
    console.log('[SOCKET] ❌ Invalid token:', err.message);
    next(new Error('Invalid token'));
  }
});

io.on('connection', (socket) => {
  console.log(`[SOCKET] 🔌 Connected: ${socket.username} (${socket.id})`);
  
  // Store connection
  connectedUsers.set(socket.userId, socket.id);
  
  // Broadcast online status
  io.emit('user:online', { userId: socket.userId, username: socket.username });
  
  // Send list of online users
  socket.emit('users:online', Array.from(connectedUsers.keys()));
  
  // ==========================================
  // MESSAGE HANDLING
  // ==========================================
  
  socket.on('message:send', async (data) => {
    try {
      const { recipientId, encryptedPayload, iv, nonce, timestamp, sequenceNumber } = data;
      
      // Store message
      const message = new Message({
        senderId: socket.userId,
        recipientId,
        encryptedPayload,
        iv,
        nonce,
        timestamp,
        sequenceNumber
      });
      await message.save();
      
      console.log(`[MESSAGE] 📨 ${socket.username} -> ${recipientId}`);
      
      // Send to recipient if online
      const recipientSocketId = connectedUsers.get(recipientId);
      if (recipientSocketId) {
        io.to(recipientSocketId).emit('message:receive', {
          messageId: message._id,
          senderId: socket.userId,
          senderUsername: socket.username,
          encryptedPayload,
          iv,
          nonce,
          timestamp,
          sequenceNumber
        });
        
        // Update status
        message.status = 'delivered';
        message.deliveredAt = new Date();
        await message.save();
      }
      
      // Acknowledge
      socket.emit('message:sent', {
        messageId: message._id,
        status: recipientSocketId ? 'delivered' : 'sent'
      });
      
      // Log
      await SecurityLog.logEvent({
        eventType: 'MESSAGE_SENT',
        severity: 'INFO',
        userId: socket.userId,
        username: socket.username,
        targetUserId: recipientId,
        result: 'SUCCESS'
      });
      
    } catch (error) {
      console.error('[MESSAGE] Error:', error.message);
      socket.emit('message:error', { error: error.message });
    }
  });
  
  // FILE HANDLING
  // ==========================================
  
  socket.on('file:send', async (data) => {
    try {
      const { recipientId, fileName, fileSize, mimeType, encryptedMetadata, encryptedData, encryption, hash, timestamp, sequenceNumber } = data;
      
      console.log(`\n[FILE] 📎 Received file from ${socket.username} (${socket.userId})`);
      console.log(`    Target recipient: ${recipientId}`);
      console.log(`    Filename: ${fileName}, Size: ${fileSize} bytes`);
      
      // Send to recipient if online
      const recipientSocketId = connectedUsers.get(recipientId);
      if (recipientSocketId) {
        console.log(`    ✅ Recipient is online, sending file...`);
        
        io.to(recipientSocketId).emit('file:receive', {
          senderId: socket.userId,
          senderUsername: socket.username,
          fileName,
          fileSize,
          mimeType,
          encryptedMetadata,
          encryptedData,
          encryption,
          hash,
          timestamp,
          sequenceNumber
        });
        
        console.log(`    ✅ File relayed successfully!`);
      } else {
        console.log(`    ⚠️  Recipient is offline`);
      }
      
      // Acknowledge to sender
      socket.emit('file:sent', {
        status: recipientSocketId ? 'delivered' : 'sent'
      });
      
      // Log
      await SecurityLog.logEvent({
        eventType: 'FILE_SENT',
        severity: 'INFO',
        userId: socket.userId,
        username: socket.username,
        targetUserId: recipientId,
        metadata: { fileName, fileSize },
        result: 'SUCCESS'
      });
      
    } catch (error) {
      console.error('[FILE] Error:', error.message);
      socket.emit('file:error', { error: error.message });
    }
  });
  
  // Message handlers
  
  // ==========================================
  // KEY EXCHANGE HANDLING
  // ==========================================
  
  socket.on('keyexchange:initiate', async (data) => {
    const { recipientId, bundle } = data;
    
    console.log(`[KEYEX] 🔑 ${socket.username} initiating with ${recipientId}`);
    
    await SecurityLog.logEvent({
      eventType: 'KEY_EXCHANGE_INITIATED',
      severity: 'INFO',
      userId: socket.userId,
      username: socket.username,
      targetUserId: recipientId,
      result: 'SUCCESS'
    });
    
    const recipientSocketId = connectedUsers.get(recipientId);
    if (recipientSocketId) {
      io.to(recipientSocketId).emit('keyexchange:request', {
        initiatorId: socket.userId,
        initiatorUsername: socket.username,
        bundle
      });
    } else {
      socket.emit('keyexchange:offline');
    }
  });
  
  socket.on('keyexchange:respond', async (data) => {
    const { initiatorId, responderId, bundle } = data;
    
    console.log(`[KEYEX] 🔑 ${socket.username} responding to ${initiatorId}`);
    
    const initiatorSocketId = connectedUsers.get(initiatorId);
    if (initiatorSocketId) {
      io.to(initiatorSocketId).emit('keyexchange:response', {
        responderId: responderId || socket.userId,
        responderUsername: socket.username,
        bundle
      });
    }
  });
  
  socket.on('keyexchange:confirm', async (data) => {
    const { partnerId, confirmation } = data;
    
    console.log(`[KEYEX] ✅ ${socket.username} confirmed with ${partnerId}`);
    
    await SecurityLog.logEvent({
      eventType: 'KEY_EXCHANGE_COMPLETED',
      severity: 'INFO',
      userId: socket.userId,
      username: socket.username,
      targetUserId: partnerId,
      result: 'SUCCESS'
    });
    
    const partnerSocketId = connectedUsers.get(partnerId);
    if (partnerSocketId) {
      io.to(partnerSocketId).emit('keyexchange:confirmed', {
        partnerId: socket.userId,
        confirmation
      });
    }
  });
  
  // ==========================================
  // TYPING INDICATORS
  // ==========================================
  
  socket.on('typing:start', ({ recipientId }) => {
    const recipientSocketId = connectedUsers.get(recipientId);
    if (recipientSocketId) {
      io.to(recipientSocketId).emit('typing:start', {
        userId: socket.userId,
        username: socket.username
      });
    }
  });
  
  socket.on('typing:stop', ({ recipientId }) => {
    const recipientSocketId = connectedUsers.get(recipientId);
    if (recipientSocketId) {
      io.to(recipientSocketId).emit('typing:stop', {
        userId: socket.userId
      });
    }
  });
  
  // ==========================================
  // DISCONNECT
  // ==========================================
  
  socket.on('disconnect', () => {
    console.log(`[SOCKET] 🔌 Disconnected: ${socket.username}`);
    connectedUsers.delete(socket.userId);
    io.emit('user:offline', { userId: socket.userId });
  });
});

// ==========================================
// DATABASE & SERVER START
// ==========================================

mongoose.connect(MONGODB_URI)
  .then(() => {
    console.log('✅ [DATABASE] Connected to MongoDB');
    
    server.listen(PORT, () => {
      console.log(`✅ [SERVER] Running on http://localhost:${PORT}`);
      console.log(`✅ [CLIENT] Expecting client on ${CLIENT_URL}`);
    });
  })
  .catch((err) => {
    console.error('❌ [DATABASE] Connection error:', err.message);
    process.exit(1);
  });

module.exports = { app, server, io };
