const mongoose = require('mongoose');

const encryptedFileSchema = new mongoose.Schema({
  ownerId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  // Encrypted metadata (filename, type, etc.)
  encryptedMetadata: {
    data: { type: String, required: true },
    iv: { type: String, required: true }
  },
  // Encryption info
  encryption: {
    algorithm: { type: String, default: 'AES-256-GCM' },
    salt: { type: String, required: true }
  },
  // File info
  originalSize: { type: Number, required: true },
  encryptedSize: { type: Number, required: true },
  totalChunks: { type: Number, required: true },
  hash: { type: String, required: true },
  // Chunks stored in filesystem
  storagePath: { type: String, required: true },
  // Sharing
  sharedWith: [{
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    encryptedKey: String,
    sharedAt: { type: Date, default: Date.now }
  }],
  // Timestamps
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model('EncryptedFile', encryptedFileSchema);
