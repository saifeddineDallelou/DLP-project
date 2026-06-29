const express = require('express');
const prisma = require('../lib/prisma');
const { authenticate, requireRole } = require('../middleware/auth');

const router = express.Router();

// ── Single attempt (agent-facing) ─────────────────────────────────────────────

// GET /api/ai-policy/attempt?agentId=  — latest attempt for an agent (quick check)
router.get('/attempt', authenticate, async (req, res, next) => {
  try {
    const { agentId } = req.query;
    const where = agentId ? { agentId } : {};

    const attempt = await prisma.aiLeakAttempt.findFirst({
      where,
      include: { agent: { select: { id: true, hostname: true } } },
      orderBy: { timestamp: 'desc' },
    });

    if (!attempt) return res.status(404).json({ error: 'No attempt found' });
    res.json(attempt);
  } catch (err) {
    next(err);
  }
});

// POST /api/ai-policy/attempt  — agent reports a new AI leak attempt
router.post('/attempt', async (req, res, next) => {
  try {
    const { agentId, platform, method, contentSample, riskScore, blocked } = req.body;

    if (!agentId || !platform || !method || riskScore == null) {
      return res.status(400).json({ error: 'agentId, platform, method and riskScore are required' });
    }

    // Agents authenticate via x-agent-token header
    const agentToken = req.headers['x-agent-token'];
    if (agentToken) {
      const agent = await prisma.agent.findUnique({ where: { id: agentId } });
      if (!agent || agent.token !== agentToken) {
        return res.status(401).json({ error: 'Unauthorized' });
      }
    } else {
      // Allow JWT-authenticated callers too (e.g. tests, admin tooling)
      const header = req.headers.authorization;
      if (!header?.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'Provide x-agent-token or Bearer token' });
      }
      const jwt = require('jsonwebtoken');
      try {
        jwt.verify(header.slice(7), process.env.JWT_SECRET);
      } catch {
        return res.status(401).json({ error: 'Invalid or expired token' });
      }
    }

    const attempt = await prisma.aiLeakAttempt.create({
      data: {
        agentId,
        platform,
        method,
        contentSample: contentSample ?? null,
        riskScore,
        blocked: blocked ?? true,
      },
    });

    res.status(201).json(attempt);
  } catch (err) {
    if (err.code === 'P2003') return res.status(404).json({ error: 'Agent not found' });
    next(err);
  }
});

// ── Bulk listing (analyst/admin-facing) ───────────────────────────────────────

// GET /api/ai-policy/attempts?platform=&method=&blocked=&agentId=&page=&limit=
router.get('/attempts', authenticate, async (req, res, next) => {
  try {
    const { platform, method, blocked, agentId, page = 1, limit = 50 } = req.query;
    const where = {};
    if (platform) where.platform = platform;
    if (method) where.method = method;
    if (agentId) where.agentId = agentId;
    if (blocked !== undefined) where.blocked = blocked === 'true';

    const skip = (Number(page) - 1) * Number(limit);
    const take = Number(limit);

    const [attempts, total] = await prisma.$transaction([
      prisma.aiLeakAttempt.findMany({
        where,
        include: { agent: { select: { id: true, hostname: true, os: true } } },
        orderBy: { timestamp: 'desc' },
        skip,
        take,
      }),
      prisma.aiLeakAttempt.count({ where }),
    ]);

    res.json({ attempts, total, page: Number(page), limit: take });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
