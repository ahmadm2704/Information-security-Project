const express = require('express');
const router = express.Router();
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const EncryptedFile = require('../models/EncryptedFile');
const SecurityLog = require('../models/SecurityLog');
const { authMiddleware } = require('../middleware/auth');

// Setup upload directory
const uploadDir = path.join(__dirname, '../uploads');
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadDir),
  filename: (req, file, cb) => cb(null, `${Date.now()}-${Math.random().toString(36).substring(7)}`)
});

const upload = multer({
  storage,
  limits: { fileSize: 100 * 1024 * 1024 } // 100MB
});

// Upload encrypted file
router.post('/upload', authMiddleware, upload.single('file'), async (req, res) => {
  try {
    const { encryptedMetadata, encryption, originalSize, totalChunks, hash } = req.body;
    
    const file = new EncryptedFile({
      ownerId: req.user.userId,
      encryptedMetadata: JSON.parse(encryptedMetadata),
      encryption: JSON.parse(encryption),
      originalSize: parseInt(originalSize),
      encryptedSize: req.file.size,
      totalChunks: parseInt(totalChunks),
      hash,
      storagePath: req.file.filename
    });
    
    await file.save();
    
    await SecurityLog.logEvent({
      eventType: 'FILE_UPLOADED',
      severity: 'INFO',
      userId: req.user.userId,
      username: req.user.username,
      details: { fileId: file._id, size: originalSize },
      result: 'SUCCESS'
    });
    
    res.json({ fileId: file._id, message: 'File uploaded' });
    
  } catch (error) {
    console.error('[FILES] Upload error:', error.message);
    res.status(500).json({ error: 'Upload failed' });
  }
});

// Get user's files
router.get('/my-files', authMiddleware, async (req, res) => {
  try {
    const files = await EncryptedFile.find({ ownerId: req.user.userId })
      .select('encryptedMetadata originalSize createdAt')
      .sort({ createdAt: -1 });
    
    res.json({ files });
    
  } catch (error) {
    res.status(500).json({ error: 'Failed to get files' });
  }
});

// Download file
router.get('/download/:fileId', authMiddleware, async (req, res) => {
  try {
    const file = await EncryptedFile.findOne({
      _id: req.params.fileId,
      $or: [
        { ownerId: req.user.userId },
        { 'sharedWith.userId': req.user.userId }
      ]
    });
    
    if (!file) {
      return res.status(404).json({ error: 'File not found' });
    }
    
    const filePath = path.join(uploadDir, file.storagePath);
    
    if (!fs.existsSync(filePath)) {
      return res.status(404).json({ error: 'File data not found' });
    }
    
    await SecurityLog.logEvent({
      eventType: 'FILE_DOWNLOADED',
      severity: 'INFO',
      userId: req.user.userId,
      details: { fileId: file._id },
      result: 'SUCCESS'
    });
    
    res.download(filePath);
    
  } catch (error) {
    res.status(500).json({ error: 'Download failed' });
  }
});

module.exports = router;
