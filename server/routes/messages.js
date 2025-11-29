const express = require('express');
const router = express.Router();
const mongoose = require('mongoose');
const Message = require('../models/Message');
const User = require('../models/User');
const { authMiddleware } = require('../middleware/auth');

// Get conversations list
router.get('/conversations', authMiddleware, async (req, res) => {
  try {
    const userId = new mongoose.Types.ObjectId(req.user.userId);
    
    const conversations = await Message.aggregate([
      {
        $match: {
          $or: [{ senderId: userId }, { recipientId: userId }]
        }
      },
      { $sort: { createdAt: -1 } },
      {
        $group: {
          _id: {
            $cond: [
              { $eq: ['$senderId', userId] },
              '$recipientId',
              '$senderId'
            ]
          },
          lastMessage: { $first: '$$ROOT' },
          unreadCount: {
            $sum: {
              $cond: [
                {
                  $and: [
                    { $eq: ['$recipientId', userId] },
                    { $ne: ['$status', 'read'] }
                  ]
                },
                1,
                0
              ]
            }
          }
        }
      },
      { $sort: { 'lastMessage.createdAt': -1 } }
    ]);
    
    // Get usernames
    const result = await Promise.all(conversations.map(async (conv) => {
      const partner = await User.findById(conv._id).select('username');
      return {
        partnerId: conv._id,
        partnerUsername: partner?.username || 'Unknown',
        lastMessageTime: conv.lastMessage.createdAt,
        unreadCount: conv.unreadCount
      };
    }));
    
    res.json({ conversations: result });
    
  } catch (error) {
    console.error('[MESSAGES] Conversations error:', error.message);
    res.status(500).json({ error: 'Failed to get conversations' });
  }
});

// Get messages with specific user
router.get('/:partnerId', authMiddleware, async (req, res) => {
  try {
    const userId = req.user.userId;
    const partnerId = req.params.partnerId;
    
    const messages = await Message.find({
      $or: [
        { senderId: userId, recipientId: partnerId },
        { senderId: partnerId, recipientId: userId }
      ]
    })
    .sort({ createdAt: 1 })
    .limit(200);
    
    // Mark as read
    await Message.updateMany(
      { senderId: partnerId, recipientId: userId, status: { $ne: 'read' } },
      { status: 'read', readAt: new Date() }
    );
    
    res.json({
      messages: messages.map(m => ({
        id: m._id,
        senderId: m.senderId,
        recipientId: m.recipientId,
        encryptedPayload: m.encryptedPayload,
        iv: m.iv,
        nonce: m.nonce,
        timestamp: m.timestamp,
        sequenceNumber: m.sequenceNumber,
        status: m.status,
        createdAt: m.createdAt
      }))
    });
    
  } catch (error) {
    console.error('[MESSAGES] Get error:', error.message);
    res.status(500).json({ error: 'Failed to get messages' });
  }
});

module.exports = router;
