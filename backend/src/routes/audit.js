const express = require('express');
const prisma = require('../lib/prisma');
const { authenticate, requireRole } = require('../middleware/auth');

const router = express.Router();

// The audit trail was write-only until this route existed: five route modules
// wrote AuditLog rows and nothing could read them back. An audit trail nobody
// can query is not an audit trail -- it is a table that grows.
//
// Read access is ADMIN/ANALYST only, matching the roles that can perform the
// audited actions in the first place. There is deliberately no write endpoint:
// audit rows are only ever created as a side effect of the action they record,
// never posted directly, so the trail cannot be forged through the API.

// GET /api/audit?resource=&action=&userId=&from=&to=&page=&limit=
router.get('/', authenticate, requireRole('ADMIN', 'ANALYST'), async (req, res, next) => {
  try {
    const { resource, action, userId, from, to } = req.query;
    const page = Math.max(1, Number(req.query.page) || 1);
    const limit = Math.min(200, Math.max(1, Number(req.query.limit) || 50));

    const where = {};
    if (resource) where.resource = resource;
    if (action) where.action = action;
    if (userId) where.userId = userId;

    if (from || to) {
      where.createdAt = {};
      if (from) {
        const d = new Date(from);
        if (isNaN(d)) return res.status(400).json({ error: 'from must be a valid date' });
        where.createdAt.gte = d;
      }
      if (to) {
        const d = new Date(to);
        if (isNaN(d)) return res.status(400).json({ error: 'to must be a valid date' });
        where.createdAt.lte = d;
      }
    }

    const [total, logs] = await Promise.all([
      prisma.auditLog.count({ where }),
      prisma.auditLog.findMany({
        where,
        include: { user: { select: { id: true, email: true, role: true } } },
        orderBy: { createdAt: 'desc' },
        skip: (page - 1) * limit,
        take: limit,
      }),
    ]);

    res.json({ total, page, limit, pages: Math.ceil(total / limit), logs });
  } catch (err) {
    next(err);
  }
});

// GET /api/audit/actions
// The distinct action/resource values actually present, so the dashboard can
// build its filter dropdowns from real data instead of a hardcoded list that
// silently drifts as new audited actions are added.
router.get('/actions', authenticate, requireRole('ADMIN', 'ANALYST'), async (_req, res, next) => {
  try {
    const [actions, resources] = await Promise.all([
      prisma.auditLog.findMany({ distinct: ['action'], select: { action: true }, orderBy: { action: 'asc' } }),
      prisma.auditLog.findMany({ distinct: ['resource'], select: { resource: true }, orderBy: { resource: 'asc' } }),
    ]);

    res.json({
      actions: actions.map(a => a.action),
      resources: resources.map(r => r.resource),
    });
  } catch (err) {
    next(err);
  }
});

// GET /api/audit/resource/:resource/:resourceId
// Every recorded action against one specific object -- the "who touched this
// incident, and when" question an auditor asks about a single case, which the
// paginated list above cannot answer without scrolling the whole trail.
router.get('/resource/:resource/:resourceId', authenticate, requireRole('ADMIN', 'ANALYST'), async (req, res, next) => {
  try {
    const logs = await prisma.auditLog.findMany({
      where: { resource: req.params.resource, resourceId: req.params.resourceId },
      include: { user: { select: { id: true, email: true, role: true } } },
      orderBy: { createdAt: 'desc' },
    });

    res.json({ resource: req.params.resource, resourceId: req.params.resourceId, logs });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
