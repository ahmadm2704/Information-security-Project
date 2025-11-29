const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const SecurityLog = require('../models/SecurityLog');
const { JWT_SECRET } = require('../middleware/auth');

const JWT_EXPIRY = '24h';

// Register
router.post('/register', async (req, res) => {
  try {
    const { username, email, password, publicKeys } = req.body;
    
    // Validation
    if (!username || !email || !password || !publicKeys) {
      return res.status(400).json({ error: 'All fields are required' });
    }
    
    if (password.length < 8) {
      return res.status(400).json({ error: 'Password must be at least 8 characters' });
    }
    
    if (!publicKeys.identityKey || !publicKeys.keyAgreementKey) {
      return res.status(400).json({ error: 'Public keys are required' });
    }
    
    // Check existing user
    const existing = await User.findOne({
      $or: [
        { username: { $regex: new RegExp(`^${username}$`, 'i') } },
        { email: email.toLowerCase() }
      ]
    });
    
    if (existing) {
      return res.status(409).json({ error: 'Username or email already exists' });
    }
    
    // Create user
    const user = new User({
      username,
      email: email.toLowerCase(),
      passwordHash: password,
      publicKeys
    });
    
    await user.save();
    
    // Generate token
    const token = jwt.sign(
      { userId: user._id, username: user.username },
      JWT_SECRET,
      { expiresIn: JWT_EXPIRY }
    );
    
    // Log
    await SecurityLog.logEvent({
      eventType: 'AUTH_REGISTER',
      severity: 'INFO',
      userId: user._id,
      username: user.username,
      request: { ip: req.ip, path: req.path },
      result: 'SUCCESS'
    });
    
    await SecurityLog.logEvent({
      eventType: 'KEY_PAIR_GENERATED',
      severity: 'INFO',
      userId: user._id,
      username: user.username,
      details: {
        identityKeyAlgorithm: publicKeys.identityKey.algorithm,
        keyAgreementAlgorithm: publicKeys.keyAgreementKey.algorithm
      },
      result: 'SUCCESS'
    });
    
    console.log(`✅ [AUTH] Registered: ${username}`);
    
    res.status(201).json({
      message: 'Registration successful',
      token,
      user: {
        id: user._id,
        username: user.username,
        email: user.email
      }
    });
    
  } catch (error) {
    console.error('[AUTH] Register error:', error.message);
    res.status(500).json({ error: 'Registration failed' });
  }
});

// Login
router.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password required' });
    }
    
    // Find user
    const user = await User.findOne({
      $or: [
        { username: { $regex: new RegExp(`^${username}$`, 'i') } },
        { email: username.toLowerCase() }
      ],
      status: 'active'
    });
    
    if (!user) {
      await SecurityLog.logEvent({
        eventType: 'AUTH_LOGIN_FAILED',
        severity: 'WARNING',
        username,
        request: { ip: req.ip, path: req.path },
        details: { reason: 'user_not_found' },
        result: 'FAILURE'
      });
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    // Check lock
    if (user.isAccountLocked()) {
      await SecurityLog.logEvent({
        eventType: 'AUTH_LOGIN_FAILED',
        severity: 'WARNING',
        userId: user._id,
        username: user.username,
        request: { ip: req.ip, path: req.path },
        details: { reason: 'account_locked' },
        result: 'BLOCKED'
      });
      return res.status(423).json({ error: 'Account locked. Try again later.' });
    }
    
    // Verify password
    const valid = await user.verifyPassword(password);
    
    if (!valid) {
      await user.incrementFailedAttempts();
      await SecurityLog.logEvent({
        eventType: 'AUTH_LOGIN_FAILED',
        severity: 'WARNING',
        userId: user._id,
        username: user.username,
        request: { ip: req.ip, path: req.path },
        details: { reason: 'wrong_password', attempts: user.security.failedLoginAttempts },
        result: 'FAILURE'
      });
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    // Success
    await user.resetFailedAttempts();
    user.security.lastLoginIP = req.ip;
    await user.save();
    
    const token = jwt.sign(
      { userId: user._id, username: user.username },
      JWT_SECRET,
      { expiresIn: JWT_EXPIRY }
    );
    
    await SecurityLog.logEvent({
      eventType: 'AUTH_LOGIN_SUCCESS',
      severity: 'INFO',
      userId: user._id,
      username: user.username,
      request: { ip: req.ip, path: req.path },
      result: 'SUCCESS'
    });
    
    console.log(`✅ [AUTH] Login: ${user.username}`);
    
    res.json({
      message: 'Login successful',
      token,
      user: {
        id: user._id,
        username: user.username,
        email: user.email
      }
    });
    
  } catch (error) {
    console.error('[AUTH] Login error:', error.message);
    res.status(500).json({ error: 'Login failed' });
  }
});

// Verify token
router.get('/verify', async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ valid: false });
    }
    
    const token = authHeader.substring(7);
    const decoded = jwt.verify(token, JWT_SECRET);
    
    const user = await User.findOne({ _id: decoded.userId, status: 'active' });
    
    if (!user) {
      return res.status(401).json({ valid: false });
    }
    
    res.json({
      valid: true,
      user: {
        id: user._id,
        username: user.username,
        email: user.email
      }
    });
    
  } catch (error) {
    res.status(401).json({ valid: false });
  }
});

// Search users
router.get('/users/search', async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).json({ error: 'Auth required' });
    
    const decoded = jwt.verify(authHeader.substring(7), JWT_SECRET);
    const { q } = req.query;
    
    if (!q || q.length < 1) {
      return res.json({ users: [] });
    }
    
    const users = await User.find({
      username: { $regex: q, $options: 'i' },
      _id: { $ne: decoded.userId },
      status: 'active'
    })
    .select('username')
    .limit(10);
    
    res.json({
      users: users.map(u => ({ id: u._id, username: u.username }))
    });
    
  } catch (error) {
    res.status(500).json({ error: 'Search failed' });
  }
});

// Logout
router.post('/logout', async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    if (authHeader) {
      try {
        const decoded = jwt.verify(authHeader.substring(7), JWT_SECRET);
        await SecurityLog.logEvent({
          eventType: 'AUTH_LOGOUT',
          severity: 'INFO',
          userId: decoded.userId,
          username: decoded.username,
          request: { ip: req.ip, path: req.path },
          result: 'SUCCESS'
        });
      } catch (e) {}
    }
    res.json({ message: 'Logged out' });
  } catch (error) {
    res.json({ message: 'Logged out' });
  }
});

module.exports = router;
