const express = require('express');
const { authenticate } = require('../middleware/auth');

const router = express.Router();

const CLASSIFIER_URL = process.env.CLASSIFIER_URL || 'http://localhost:8000';

// POST /api/classify — proxies to the classifier microservice (regex + Luhn +
// keyword engine) instead of re-implementing detection here, so there is one
// source of truth for what counts as sensitive content.
router.post('/', authenticate, async (req, res, next) => {
  const { content, channel } = req.body;
  if (!content) return res.status(400).json({ error: 'content is required' });

  let upstream;
  try {
    upstream = await fetch(`${CLASSIFIER_URL}/classify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ text: content }),
    });
  } catch (err) {
    return res.status(503).json({ error: 'Classifier service unavailable' });
  }

  if (!upstream.ok) {
    const detail = await upstream.text().catch(() => '');
    return res.status(502).json({ error: 'Classifier service error', detail });
  }

  try {
    const result = await upstream.json();
    const riskScore  = result.risk_score;
    const detections = result.detections ?? [];

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
      sensitive: result.sensitive,
      riskScore,
      recommendedAction,
      categories: detections.map((d) => d.type),
      detections,
      evidenceExcerpt: result.evidence_excerpt,
      channel: channel || null,
    });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
