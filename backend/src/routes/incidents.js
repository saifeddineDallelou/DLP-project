const express = require('express');
const prisma = require('../lib/prisma');
const { authenticate, requireRole } = require('../middleware/auth');

const router = express.Router();

// GET /api/incidents  (paginated, filterable)
router.get('/', authenticate, async (req, res, next) => {
  try {
    const { status, severity, agentId, page = 1, limit = 20 } = req.query;
    const where = {};
    if (status) where.status = status;
    if (severity) where.severity = severity;
    if (agentId) where.agentId = agentId;

    const skip = (Number(page) - 1) * Number(limit);
    const take = Number(limit);

    const [incidents, total] = await prisma.$transaction([
      prisma.incident.findMany({
        where,
        include: {
          agent: { select: { id: true, hostname: true, os: true } },
          policy: { select: { id: true, name: true, action: true } },
          assignedTo: { select: { id: true, email: true, role: true } },
        },
        orderBy: { createdAt: 'desc' },
        skip,
        take,
      }),
      prisma.incident.count({ where }),
    ]);

    res.json({ incidents, total, page: Number(page), limit: take });
  } catch (err) {
    next(err);
  }
});

// GET /api/incidents/:id
router.get('/:id', authenticate, async (req, res, next) => {
  try {
    const incident = await prisma.incident.findUnique({
      where: { id: req.params.id },
      include: {
        agent: true,
        policy: true,
        assignedTo: { select: { id: true, email: true, role: true } },
      },
    });
    if (!incident) return res.status(404).json({ error: 'Incident not found' });
    res.json(incident);
  } catch (err) {
    next(err);
  }
});

// PATCH /api/incidents/:id
router.patch('/:id', authenticate, requireRole('ADMIN', 'ANALYST'), async (req, res, next) => {
  try {
    const { status, assignedToId, riskScore } = req.body;
    const data = {};
    if (status) data.status = status;
    if (assignedToId !== undefined) data.assignedToId = assignedToId;
    if (riskScore !== undefined) data.riskScore = riskScore;
    if (status === 'RESOLVED') data.resolvedAt = new Date();

    const incident = await prisma.incident.update({ where: { id: req.params.id }, data });

    await prisma.auditLog.create({
      data: {
        userId: req.user.sub,
        action: 'UPDATE_INCIDENT',
        resource: 'incident',
        resourceId: incident.id,
        ipAddress: req.ip,
        metadata: { status, assignedToId },
      },
    });

    res.json(incident);
  } catch (err) {
    if (err.code === 'P2025') return res.status(404).json({ error: 'Incident not found' });
    next(err);
  }
});

module.exports = router;
