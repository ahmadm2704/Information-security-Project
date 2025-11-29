const mongoose = require('mongoose');

const securityLogSchema = new mongoose.Schema({
  eventType: {
    type: String,
    required: true,
    enum: [
      'AUTH_LOGIN_SUCCESS',
      'AUTH_LOGIN_FAILED',
      'AUTH_REGISTER',
      'AUTH_LOGOUT',
      'AUTH_PASSWORD_CHANGE',
      'AUTH_ACCOUNT_LOCKED',
      'KEY_PAIR_GENERATED',
      'KEY_EXCHANGE_INITIATED',
      'KEY_EXCHANGE_COMPLETED',
      'KEY_EXCHANGE_FAILED',
      'MESSAGE_SENT',
      'MESSAGE_DELIVERED',
      'REPLAY_ATTACK_DETECTED',
      'INVALID_SIGNATURE_DETECTED',
      'INVALID_TIMESTAMP_DETECTED',
      'UNAUTHORIZED_ACCESS',
      'RATE_LIMIT_EXCEEDED',
      'FILE_UPLOADED',
      'FILE_DOWNLOADED',
      'FILE_SHARED'
    ]
  },
  severity: {
    type: String,
    enum: ['INFO', 'WARNING', 'ERROR', 'CRITICAL'],
    default: 'INFO'
  },
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  },
  username: String,
  targetUserId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  },
  request: {
    ip: String,
    userAgent: String,
    path: String,
    method: String
  },
  details: {
    type: mongoose.Schema.Types.Mixed
  },
  result: {
    type: String,
    enum: ['SUCCESS', 'FAILURE', 'BLOCKED', 'LOGGED'],
    default: 'LOGGED'
  },
  timestamp: {
    type: Date,
    default: Date.now
  }
});

// Index for efficient queries
securityLogSchema.index({ eventType: 1, timestamp: -1 });
securityLogSchema.index({ userId: 1, timestamp: -1 });
securityLogSchema.index({ severity: 1, timestamp: -1 });

// Static method to log events
securityLogSchema.statics.logEvent = async function(data) {
  try {
    const log = new this(data);
    await log.save();
    
    // Console output for monitoring
    const icon = {
      'INFO': 'ℹ️',
      'WARNING': '⚠️',
      'ERROR': '❌',
      'CRITICAL': '🚨'
    }[data.severity] || '📝';
    
    console.log(`${icon} [SECURITY] ${data.eventType} - ${data.result || 'LOGGED'}`);
    
    return log;
  } catch (error) {
    console.error('[SECURITY LOG ERROR]', error.message);
  }
};

module.exports = mongoose.model('SecurityLog', securityLogSchema);
