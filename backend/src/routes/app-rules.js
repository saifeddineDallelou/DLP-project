const express = require('express');
const jwt = require('jsonwebtoken');
const prisma = require('../lib/prisma');
const { authenticate, requireRole } = require('../middleware/auth');

const router = express.Router();

// GET /api/app-rules  (JWT Bearer OR x-agent-token -- the agent fetches this
// list at startup and periodically, same pattern as GET /api/policies)
router.get('/', async (req, res, next) => {
  try {
    const agentToken = req.headers['x-agent-token'];
    if (agentToken) {
      const agent = await prisma.agent.findFirst({ where: { token: agentToken } });
      if (!agent) return res.status(401).json({ error: 'Invalid agent token' });
    } else {
      const authHeader = req.headers.authorization;
      if (!authHeader?.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'Missing or invalid authorization header' });
      }
      try {
        jwt.verify(authHeader.slice(7), process.env.JWT_SECRET);
      } catch {
        return res.status(401).json({ error: 'Invalid or expired token' });
      }
    }

    const { enabled } = req.query;
    const where = enabled !== undefined ? { enabled: enabled === 'true' } : {};
    const rules = await prisma.appRule.findMany({ where, orderBy: { createdAt: 'desc' } });
    res.json(rules);
  } catch (err) {
    next(err);
  }
});

// POST /api/app-rules
router.post('/', authenticate, requireRole('ADMIN', 'ANALYST'), async (req, res, next) => {
  try {
    const { keyword, label, enabled } = req.body;
    if (!keyword || !label) {
      return res.status(400).json({ error: 'keyword and label are required' });
    }

    const rule = await prisma.appRule.create({
      data: { keyword: keyword.toLowerCase(), label, enabled: enabled ?? true },
    });

    await prisma.auditLog.create({
      data: {
        userId: req.user.sub,
        action: 'CREATE_APP_RULE',
        resource: 'app_rule',
        resourceId: rule.id,
        ipAddress: req.ip,
        metadata: { keyword: rule.keyword },
      },
    });

    res.status(201).json(rule);
  } catch (err) {
    if (err.code === 'P2002') return res.status(409).json({ error: 'A rule for this keyword already exists' });
    next(err);
  }
});

// PUT /api/app-rules/:id
router.put('/:id', authenticate, requireRole('ADMIN', 'ANALYST'), async (req, res, next) => {
  try {
    const { keyword, label, enabled } = req.body;

    const rule = await prisma.appRule.update({
      where: { id: req.params.id },
      data: {
        ...(keyword !== undefined && { keyword: keyword.toLowerCase() }),
        ...(label !== undefined && { label }),
        ...(enabled !== undefined && { enabled }),
      },
    });

    await prisma.auditLog.create({
      data: {
        userId: req.user.sub,
        action: 'UPDATE_APP_RULE',
        resource: 'app_rule',
        resourceId: rule.id,
        ipAddress: req.ip,
      },
    });

    res.json(rule);
  } catch (err) {
    if (err.code === 'P2025') return res.status(404).json({ error: 'App rule not found' });
    if (err.code === 'P2002') return res.status(409).json({ error: 'A rule for this keyword already exists' });
    next(err);
  }
});

// DELETE /api/app-rules/:id  (ADMIN only)
router.delete('/:id', authenticate, requireRole('ADMIN'), async (req, res, next) => {
  try {
    await prisma.appRule.delete({ where: { id: req.params.id } });

    await prisma.auditLog.create({
      data: {
        userId: req.user.sub,
        action: 'DELETE_APP_RULE',
        resource: 'app_rule',
        resourceId: req.params.id,
        ipAddress: req.ip,
      },
    });

    res.status(204).send();
  } catch (err) {
    if (err.code === 'P2025') return res.status(404).json({ error: 'App rule not found' });
    next(err);
  }
});

module.exports = router;
