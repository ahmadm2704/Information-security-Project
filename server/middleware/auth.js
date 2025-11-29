const jwt = require('jsonwebtoken');
const SecurityLog = require('../models/SecurityLog');

const JWT_SECRET = process.env.JWT_SECRET || 'securecomm-super-secret-jwt-key-2024-change-in-production';

const authMiddleware = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      await SecurityLog.logEvent({
        eventType: 'UNAUTHORIZED_ACCESS',
        severity: 'WARNING',
        request: {
          ip: req.ip,
          path: req.path,
          method: req.method,
          userAgent: req.headers['user-agent']
        },
        details: { reason: 'no_token' },
        result: 'BLOCKED'
      });
      
      return res.status(401).json({ error: 'Authentication required' });
    }
    
    const token = authHeader.substring(7);
    
    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      req.user = {
        userId: decoded.userId,
        username: decoded.username
      };
      next();
    } catch (jwtError) {
      return res.status(401).json({ error: 'Invalid or expired token' });
    }
    
  } catch (error) {
    console.error('[AUTH MIDDLEWARE]', error.message);
    res.status(500).json({ error: 'Authentication failed' });
  }
};

module.exports = { authMiddleware, JWT_SECRET };
