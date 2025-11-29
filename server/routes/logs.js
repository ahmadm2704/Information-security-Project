const express = require('express');
const router = express.Router();
const SecurityLog = require('../models/SecurityLog');
const { authMiddleware } = require('../middleware/auth');

// Get security logs for current user
router.get('/', authMiddleware, async (req, res) => {
  try {
    const { type, severity, limit = 50, page = 1 } = req.query;
    
    const query = { userId: req.user.userId };
    
    if (type) query.eventType = type;
    if (severity) query.severity = severity;
    
    const logs = await SecurityLog.find(query)
      .sort({ timestamp: -1 })
      .skip((page - 1) * limit)
      .limit(parseInt(limit));
    
    const total = await SecurityLog.countDocuments(query);
    
    res.json({
      logs,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total,
        pages: Math.ceil(total / limit)
      }
    });
    
  } catch (error) {
    res.status(500).json({ error: 'Failed to get logs' });
  }
});

// Get summary stats
router.get('/summary', authMiddleware, async (req, res) => {
  try {
    const userId = req.user.userId;
    const last24h = new Date(Date.now() - 24 * 60 * 60 * 1000);
    
    const stats = await SecurityLog.aggregate([
      { $match: { userId, timestamp: { $gte: last24h } } },
      {
        $group: {
          _id: '$eventType',
          count: { $sum: 1 }
        }
      }
    ]);
    
    const criticalCount = await SecurityLog.countDocuments({
      userId,
      severity: 'CRITICAL',
      timestamp: { $gte: last24h }
    });
    
    res.json({
      last24Hours: stats,
      criticalAlerts: criticalCount
    });
    
  } catch (error) {
    res.status(500).json({ error: 'Failed to get summary' });
  }
});

module.exports = router;
