const mongoose = require('mongoose');

const messageSchema = new mongoose.Schema({
  senderId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  recipientId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  // Encrypted content (server never sees plaintext)
  encryptedPayload: {
    type: String,
    required: true
  },
  // Initialization vector for AES-GCM
  iv: {
    type: String,
    required: true
  },
  // For replay attack protection
  nonce: {
    type: String,
    required: true
  },
  timestamp: {
    type: Number,
    required: true
  },
  sequenceNumber: {
    type: Number,
    required: true
  },
  // Message status
  status: {
    type: String,
    enum: ['sent', 'delivered', 'read'],
    default: 'sent'
  },
  deliveredAt: Date,
  readAt: Date,
  createdAt: {
    type: Date,
    default: Date.now
  }
});

// Index for efficient queries
messageSchema.index({ senderId: 1, recipientId: 1, createdAt: -1 });
messageSchema.index({ nonce: 1 }, { unique: true });

module.exports = mongoose.model('Message', messageSchema);
