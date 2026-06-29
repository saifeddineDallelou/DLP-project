const express = require('express');
const { authenticate } = require('../middleware/auth');

const router = express.Router();

const DETECTORS = {
  EMAIL:       /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/,
  CREDIT_CARD: /\b(?:\d[ -]?){13,16}\b/,
  SSN:         /\b\d{3}-\d{2}-\d{4}\b/,
  PHONE:       /\b\d{3}[-.]?\d{3}[-.]?\d{4}\b/,
  IP_ADDRESS:  /\b(?:\d{1,3}\.){3}\d{1,3}\b/,
};

// POST /api/classify
router.post('/', authenticate, (req, res) => {
  const { content, channel } = req.body;
  if (!content) return res.status(400).json({ error: 'content is required' });

  const categories = Object.entries(DETECTORS)
    .filter(([, re]) => re.test(content))
    .map(([name]) => name);

  const riskScore = Math.min(categories.length * 0.25, 1.0);

  let classification = 'PUBLIC';
  let recommendedAction = 'ALLOW';

  if (riskScore >= 0.75) {
    classification = 'RESTRICTED';
    recommendedAction = 'BLOCK';
  } else if (riskScore >= 0.5) {
    classification = 'CONFIDENTIAL';
    recommendedAction = 'ALERT';
  } else if (riskScore > 0) {
    classification = 'INTERNAL';
    recommendedAction = 'ALERT';
  }

  res.json({
    classification,
    confidence: categories.length > 0 ? 0.85 + riskScore * 0.1 : 0.95,
    categories,
    riskScore,
    recommendedAction,
    channel: channel || null,
  });
});

module.exports = router;
