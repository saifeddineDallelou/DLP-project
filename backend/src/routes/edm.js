const express = require('express');
const prisma = require('../lib/prisma');
const { authenticate, requireRole } = require('../middleware/auth');

const router = express.Router();

const CLASSIFIER_URL = process.env.CLASSIFIER_URL || 'http://localhost:8000';

// Exact Data Match reference sets, proxied to the classifier.
//
// The classifier owns EDM entirely -- it holds the salt and the digests, and
// it is deliberately the only component that decides what is sensitive. This
// router adds the two things the classifier has no business doing: dashboard
// AUTHENTICATION, and an AUDIT TRAIL of who indexed or removed which set.
//
// The upload path is the reason the proxy exists at all. Its body carries
// REAL customer records in transit -- the one moment they exist outside the
// customer's own database -- and src/edm.py says so plainly: "this endpoint
// belongs behind the backend's authenticated proxy in any deployment where
// the classifier is not on localhost". Exposing :8000 to the dashboard
// directly would put an unauthenticated bulk-PII intake on the network.
//
// Rows are forwarded and never persisted here. They are not logged, not
// echoed back, and the audit row records the set NAME and column COUNT only.

async function callClassifier(path, init) {
  try {
    return await fetch(`${CLASSIFIER_URL}${path}`, init);
  } catch {
    return null;
  }
}

function unavailable(res) {
  return res.status(503).json({ error: 'Classifier service unavailable' });
}

// GET /api/edm — configured reference sets. Counts and column names only;
// the classifier never returns digests over its own API either.
router.get('/', authenticate, async (_req, res, next) => {
  try {
    const upstream = await callClassifier('/edm', { method: 'GET' });
    if (!upstream) return unavailable(res);
    if (!upstream.ok) {
      return res.status(502).json({ error: 'Classifier service error' });
    }
    res.json(await upstream.json());
  } catch (err) {
    next(err);
  }
});

// POST /api/edm — index a set of real records.
router.post('/', authenticate, requireRole('ADMIN', 'ANALYST'), async (req, res, next) => {
  try {
    const { name, rows, rule, min_fields: minFields } = req.body;
    if (!name || !String(name).trim()) {
      return res.status(400).json({ error: 'name is required' });
    }
    if (!Array.isArray(rows) || rows.length === 0) {
      return res.status(400).json({ error: 'rows must be a non-empty array' });
    }

    const upstream = await callClassifier('/edm', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        name: String(name).trim(),
        rows,
        rule: rule || 'INTERNAL',
        min_fields: Number(minFields) || 1,
      }),
    });
    if (!upstream) return unavailable(res);

    const body = await upstream.json().catch(() => ({}));
    if (!upstream.ok) {
      // Surface the classifier's own explanation -- it is the component that
      // knows why a set was rejected (too-short values, min_fields exceeding
      // the column count) and its messages say what to do about it.
      return res.status(upstream.status).json({
        error: body.detail || 'Classifier rejected the reference set',
      });
    }

    await prisma.auditLog.create({
      data: {
        userId: req.user.sub,
        action: 'CREATE_EDM_SET',
        resource: 'edm_reference_set',
        resourceId: body.name ?? String(name).trim(),
        ipAddress: req.ip,
        // Deliberately no row content: shape only. An audit trail that
        // recorded what was indexed would recreate the concentration of
        // customer data that hashing exists to avoid.
        metadata: {
          rowsSubmitted: rows.length,
          columns: Object.keys(body.columns ?? {}).length,
          minFields: body.minFields ?? 1,
          rule: body.rule ?? null,
        },
      },
    });

    res.status(201).json(body);
  } catch (err) {
    next(err);
  }
});

// DELETE /api/edm/:name — ADMIN only. Removing a reference set silently stops
// every detection it was providing, which is a bigger change than it looks.
router.delete('/:name', authenticate, requireRole('ADMIN'), async (req, res, next) => {
  try {
    const upstream = await callClassifier(`/edm/${encodeURIComponent(req.params.name)}`, {
      method: 'DELETE',
    });
    if (!upstream) return unavailable(res);
    if (upstream.status === 404) {
      return res.status(404).json({ error: `No reference set named '${req.params.name}'` });
    }
    if (!upstream.ok) {
      return res.status(502).json({ error: 'Classifier service error' });
    }

    await prisma.auditLog.create({
      data: {
        userId: req.user.sub,
        action: 'DELETE_EDM_SET',
        resource: 'edm_reference_set',
        resourceId: req.params.name,
        ipAddress: req.ip,
      },
    });

    res.status(204).end();
  } catch (err) {
    next(err);
  }
});

module.exports = router;
