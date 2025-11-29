const express = require('express');
const router = express.Router();
const User = require('../models/User');
const SecurityLog = require('../models/SecurityLog');
const { authMiddleware } = require('../middleware/auth');

// Get user's public key bundle
router.get('/bundle/:userId', authMiddleware, async (req, res) => {
  try {
    console.log('[KEYS] Fetching bundle for userId:', req.params.userId);
    const user = await User.findById(req.params.userId)
      .select('username publicKeys');
    
    console.log('[KEYS] User found:', user ? user.username : 'NOT FOUND');
    
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    res.json({
      userId: user._id,
      username: user.username,
      publicKeys: user.publicKeys
    });
    
  } catch (error) {
    console.error('[KEYS] Bundle error:', error.message);
    res.status(500).json({ error: 'Failed to get key bundle' });
  }
});

// Log key exchange
router.post('/exchange/log', authMiddleware, async (req, res) => {
  try {
    const { partnerId, status, error: errorMsg } = req.body;
    
    await SecurityLog.logEvent({
      eventType: status === 'success' ? 'KEY_EXCHANGE_COMPLETED' : 'KEY_EXCHANGE_FAILED',
      severity: status === 'success' ? 'INFO' : 'WARNING',
      userId: req.user.userId,
      username: req.user.username,
      targetUserId: partnerId,
      details: { error: errorMsg },
      result: status === 'success' ? 'SUCCESS' : 'FAILURE'
    });
    
    res.json({ logged: true });
    
  } catch (error) {
    res.status(500).json({ error: 'Failed to log' });
  }
});

module.exports = router;
