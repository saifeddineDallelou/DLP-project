const express = require('express');
const prisma = require('../lib/prisma');
const { authenticate, requireRole } = require('../middleware/auth');

const router = express.Router();

// GET /api/policies
router.get('/', authenticate, async (req, res, next) => {
  try {
    const { enabled } = req.query;
    const where = enabled !== undefined ? { enabled: enabled === 'true' } : {};
    const policies = await prisma.policy.findMany({
      where,
      orderBy: { createdAt: 'desc' },
    });
    res.json(policies);
  } catch (err) {
    next(err);
  }
});

// GET /api/policies/:id
router.get('/:id', authenticate, async (req, res, next) => {
  try {
    const policy = await prisma.policy.findUnique({ where: { id: req.params.id } });
    if (!policy) return res.status(404).json({ error: 'Policy not found' });
    res.json(policy);
  } catch (err) {
    next(err);
  }
});

// POST /api/policies
router.post('/', authenticate, requireRole('ADMIN', 'ANALYST'), async (req, res, next) => {
  try {
    const { name, description, conditions, action, severity } = req.body;
    if (!name || !conditions) {
      return res.status(400).json({ error: 'name and conditions are required' });
    }

    const policy = await prisma.policy.create({
      data: { name, description, conditions, action, severity },
    });

    await prisma.auditLog.create({
      data: {
        userId: req.user.sub,
        action: 'CREATE_POLICY',
        resource: 'policy',
        resourceId: policy.id,
        ipAddress: req.ip,
        metadata: { name },
      },
    });

    res.status(201).json(policy);
  } catch (err) {
    next(err);
  }
});

// PUT /api/policies/:id
router.put('/:id', authenticate, requireRole('ADMIN', 'ANALYST'), async (req, res, next) => {
  try {
    const { name, description, conditions, action, severity, enabled } = req.body;

    const policy = await prisma.policy.update({
      where: { id: req.params.id },
      data: {
        ...(name !== undefined && { name }),
        ...(description !== undefined && { description }),
        ...(conditions !== undefined && { conditions }),
        ...(action !== undefined && { action }),
        ...(severity !== undefined && { severity }),
        ...(enabled !== undefined && { enabled }),
        version: { increment: 1 },
      },
    });

    await prisma.auditLog.create({
      data: {
        userId: req.user.sub,
        action: 'UPDATE_POLICY',
        resource: 'policy',
        resourceId: policy.id,
        ipAddress: req.ip,
      },
    });

    res.json(policy);
  } catch (err) {
    if (err.code === 'P2025') return res.status(404).json({ error: 'Policy not found' });
    next(err);
  }
});

// DELETE /api/policies/:id  (ADMIN only)
router.delete('/:id', authenticate, requireRole('ADMIN'), async (req, res, next) => {
  try {
    await prisma.policy.delete({ where: { id: req.params.id } });

    await prisma.auditLog.create({
      data: {
        userId: req.user.sub,
        action: 'DELETE_POLICY',
        resource: 'policy',
        resourceId: req.params.id,
        ipAddress: req.ip,
      },
    });

    res.status(204).send();
  } catch (err) {
    if (err.code === 'P2025') return res.status(404).json({ error: 'Policy not found' });
    next(err);
  }
});

module.exports = router;
