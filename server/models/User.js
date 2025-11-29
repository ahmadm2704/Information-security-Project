const mongoose = require('mongoose');
const bcrypt = require('bcrypt');

const userSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    minlength: 3,
    maxlength: 30
  },
  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
    trim: true
  },
  passwordHash: {
    type: String,
    required: true
  },
  publicKeys: {
    identityKey: {
      algorithm: { type: String, default: 'ECDSA-P256' },
      publicKey: { type: String, required: true }
    },
    keyAgreementKey: {
      algorithm: { type: String, default: 'ECDH-P256' },
      publicKey: { type: String, required: true }
    }
  },
  status: {
    type: String,
    enum: ['active', 'suspended', 'deleted'],
    default: 'active'
  },
  security: {
    failedLoginAttempts: { type: Number, default: 0 },
    accountLockedUntil: { type: Date, default: null },
    lastLoginAt: { type: Date },
    lastLoginIP: { type: String }
  },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

// Hash password before saving
userSchema.pre('save', async function(next) {
  this.updatedAt = new Date();
  
  if (this.isModified('passwordHash') && !this.passwordHash.startsWith('$2')) {
    this.passwordHash = await bcrypt.hash(this.passwordHash, 12);
  }
  next();
});

// Verify password
userSchema.methods.verifyPassword = async function(password) {
  return bcrypt.compare(password, this.passwordHash);
};

// Check if account is locked
userSchema.methods.isAccountLocked = function() {
  if (this.security.accountLockedUntil && this.security.accountLockedUntil > new Date()) {
    return true;
  }
  return false;
};

// Increment failed login attempts
userSchema.methods.incrementFailedAttempts = async function() {
  this.security.failedLoginAttempts += 1;
  
  if (this.security.failedLoginAttempts >= 5) {
    this.security.accountLockedUntil = new Date(Date.now() + 15 * 60 * 1000); // 15 minutes
  }
  
  await this.save();
};

// Reset failed attempts
userSchema.methods.resetFailedAttempts = async function() {
  this.security.failedLoginAttempts = 0;
  this.security.accountLockedUntil = null;
  this.security.lastLoginAt = new Date();
  await this.save();
};

module.exports = mongoose.model('User', userSchema);
