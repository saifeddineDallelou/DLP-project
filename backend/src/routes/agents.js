const express = require('express');
const { randomUUID } = require('crypto');
const prisma = require('../lib/prisma');
const { authenticate, requireRole } = require('../middleware/auth');

const router = express.Router();

// GET /api/agents
router.get('/', authenticate, async (req, res, next) => {
  try {
    const { status } = req.query;
    const where = status ? { status } : {};
    const agents = await prisma.agent.findMany({
      where,
      select: { id: true, hostname: true, os: true, version: true, status: true, lastSeen: true, createdAt: true },
      orderBy: { createdAt: 'desc' },
    });
    res.json(agents);
  } catch (err) {
    next(err);
  }
});

// GET /api/agents/:id
router.get('/:id', authenticate, async (req, res, next) => {
  try {
    const agent = await prisma.agent.findUnique({
      where: { id: req.params.id },
      select: { id: true, hostname: true, os: true, version: true, status: true, lastSeen: true, createdAt: true },
    });
    if (!agent) return res.status(404).json({ error: 'Agent not found' });
    res.json(agent);
  } catch (err) {
    next(err);
  }
});

// POST /api/agents/enroll  (no auth — called by the endpoint agent itself)
router.post('/enroll', async (req, res, next) => {
  try {
    const { hostname, os, version } = req.body;
    if (!hostname || !os) {
      return res.status(400).json({ error: 'hostname and os are required' });
    }

    const token = randomUUID();
    const agent = await prisma.agent.create({
      data: { hostname, os, version: version || '1.0.0', token },
    });

    // Return token only on enrollment — never exposed again
    res.status(201).json({ id: agent.id, hostname: agent.hostname, token: agent.token });
  } catch (err) {
    if (err.code === 'P2002') {
      return res.status(409).json({ error: 'Agent with this hostname is already enrolled' });
    }
    next(err);
  }
});

// PATCH /api/agents/:id/heartbeat  (authenticated by agent token header)
router.patch('/:id/heartbeat', async (req, res, next) => {
  try {
    const agentToken = req.headers['x-agent-token'];
    const agent = await prisma.agent.findUnique({ where: { id: req.params.id } });
    if (!agent || agent.token !== agentToken) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    const updated = await prisma.agent.update({
      where: { id: req.params.id },
      data: { lastSeen: new Date(), status: 'ACTIVE' },
      select: { id: true, hostname: true, status: true, lastSeen: true },
    });
    res.json(updated);
  } catch (err) {
    next(err);
  }
});

// DELETE /api/agents/:id  (ADMIN only)
router.delete('/:id', authenticate, requireRole('ADMIN'), async (req, res, next) => {
  try {
    await prisma.agent.delete({ where: { id: req.params.id } });
    res.status(204).send();
  } catch (err) {
    if (err.code === 'P2025') return res.status(404).json({ error: 'Agent not found' });
    next(err);
  }
});

module.exports = router;
