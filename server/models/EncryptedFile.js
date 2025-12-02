const mongoose = require('mongoose');

const encryptedFileSchema = new mongoose.Schema({
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
  fileName: { type: String, required: true },
  fileSize: { type: Number, required: true },
  mimeType: { type: String, default: 'application/octet-stream' },
  // Encrypted metadata (filename, type, etc.)
  encryptedMetadata: {
    data: { type: String, required: true },
    iv: { type: String, required: true }
  },
  // Encrypted file data
  encryptedData: {
    data: { type: String, required: true },
    iv: { type: String, required: true }
  },
  // Encryption info
  encryption: {
    algorithm: { type: String, default: 'AES-256-GCM' },
    salt: { type: String, required: true }
  },
  // File hash for integrity
  hash: { type: String, required: true },
  // Message metadata
  timestamp: { type: Date, default: Date.now },
  sequenceNumber: { type: Number },
  status: { type: String, enum: ['sent', 'delivered', 'failed'], default: 'sent' },
  deliveredAt: Date,
  // Timestamps
  createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model('EncryptedFile', encryptedFileSchema);
