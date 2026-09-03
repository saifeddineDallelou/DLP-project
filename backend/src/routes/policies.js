const express = require('express');

// Valid Action values, mirrored from prisma/schema.prisma. A per-channel
// override that is not one of these would be stored happily by Postgres --
// the column is Json -- and then reach an endpoint agent as the action it
// enforces. Rejected here, where the caller can be told why.
const ACTIONS = ['ALLOW', 'ALERT', 'BLOCK', 'QUARANTINE'];
const SEVERITIES = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];

// The channels a monitor can report. QUARANTINE only means anything for FILE:
// a file at rest has no in-flight action to stop, and equally a paste cannot
// be moved to a quarantine folder. Validating the pair stops a policy that
// silently does nothing -- which is exactly what BLOCK on FILE used to be.
const CHANNELS = ['FILE', 'FILE_UPLOAD', 'CLIPBOARD', 'SCREENSHOT', 'PRINT', 'USB', 'NETWORK'];
const AT_REST = new Set(['FILE']);

// A risk ladder: at each confidence threshold, an action and a severity.
//
//   [{minRisk: 0.9, action: 'QUARANTINE', severity: 'CRITICAL'},
//    {minRisk: 0.7, action: 'ALERT',      severity: 'HIGH'}]
//
// Validated here because these end up deciding what an endpoint agent does to
// somebody's files, and the column is Json -- Postgres would store anything.
function validateTiers(tiers) {
  if (tiers === undefined || tiers === null) return null;
  if (!Array.isArray(tiers)) return 'tiers must be an array';
  if (tiers.length === 0) return null;

  const seen = new Set();
  for (const tier of tiers) {
    if (typeof tier !== 'object' || tier === null || Array.isArray(tier)) {
      return 'each tier must be an object with minRisk, action and severity';
    }
    // Number(null) is 0 and Number('') is 0, so an omitted threshold would
    // silently become the BROADEST possible rung -- "applies to everything"
    // created by leaving a field out.
    const risk = (tier.minRisk === null || tier.minRisk === undefined || tier.minRisk === '')
      ? NaN
      : Number(tier.minRisk);
    if (!Number.isFinite(risk) || risk < 0 || risk > 1) {
      return `minRisk must be a number between 0 and 1 (got ${JSON.stringify(tier.minRisk)})`;
    }
    if (seen.has(risk)) {
      // Two rungs at the same threshold: which one applies would depend on
      // array order, which is not something an admin should have to reason
      // about.
      return `Two tiers share minRisk ${risk}. Each threshold must be distinct.`;
    }
    seen.add(risk);
    const action = String(tier.action ?? '').toUpperCase();
    if (!ACTIONS.includes(action)) {
      return `Invalid action '${tier.action}' at minRisk ${risk}. Valid: ${ACTIONS.join(', ')}`;
    }
    if (tier.severity !== undefined && tier.severity !== null
        && !SEVERITIES.includes(String(tier.severity).toUpperCase())) {
      return `Invalid severity '${tier.severity}' at minRisk ${risk}. Valid: ${SEVERITIES.join(', ')}`;
    }
  }

  // A ladder that gets SOFTER as confidence rises is almost certainly a
  // mistake, and a silent one -- the strongest evidence would get the weakest
  // response.
  const rank = { ALLOW: 0, ALERT: 1, BLOCK: 2, QUARANTINE: 2 };
  const sorted = [...tiers].sort((a, b) => Number(a.minRisk) - Number(b.minRisk));
  for (let i = 1; i < sorted.length; i++) {
    const lower = rank[String(sorted[i - 1].action).toUpperCase()];
    const upper = rank[String(sorted[i].action).toUpperCase()];
    if (upper < lower) {
      return `Tier at minRisk ${sorted[i].minRisk} responds more weakly than the one `
           + `below it (${sorted[i].action} after ${sorted[i - 1].action}). Higher `
           + `confidence should not mean a softer response.`;
    }
  }
  return null;
}

function validateChannelActions(channelActions) {
  if (channelActions === undefined || channelActions === null) return null;
  if (typeof channelActions !== 'object' || Array.isArray(channelActions)) {
    return 'channelActions must be an object of channel -> action';
  }
  for (const [channel, action] of Object.entries(channelActions)) {
    const ch = String(channel).toUpperCase();
    if (!CHANNELS.includes(ch)) {
      return `Unknown channel '${channel}'. Valid: ${CHANNELS.join(', ')}`;
    }
    if (!ACTIONS.includes(String(action).toUpperCase())) {
      return `Invalid action '${action}' for ${ch}. Valid: ${ACTIONS.join(', ')}`;
    }
    const act = String(action).toUpperCase();
    if (act === 'QUARANTINE' && !AT_REST.has(ch)) {
      return `QUARANTINE is only meaningful for data at rest (${[...AT_REST].join(', ')}). `
           + `${ch} is an action in flight -- use BLOCK.`;
    }
    if (act === 'BLOCK' && AT_REST.has(ch)) {
      return `BLOCK cannot stop a file that is already at rest -- there is nothing in `
           + `flight to intercept, so it would only record an incident. Use QUARANTINE `
           + `to remove the file, or ALERT if recording is what you want.`;
    }
  }
  return null;
}
const jwt = require('jsonwebtoken');
const prisma = require('../lib/prisma');
const { authenticate, requireRole } = require('../middleware/auth');

const router = express.Router();

// GET /api/policies  (JWT Bearer OR x-agent-token -- the endpoint agent
// reads policies at startup to pick the right compliance policy for each
// incident it creates, based on what the classifier actually detected)
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
        req.user = jwt.verify(authHeader.slice(7), process.env.JWT_SECRET);
      } catch {
        return res.status(401).json({ error: 'Invalid or expired token' });
      }
    }

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
    const { name, description, conditions, action, severity, channelActions, tiers } = req.body;
    if (!name || !conditions) {
      return res.status(400).json({ error: 'name and conditions are required' });
    }
    const channelError = validateChannelActions(channelActions);
    if (channelError) return res.status(400).json({ error: channelError });
    const tierError = validateTiers(tiers);
    if (tierError) return res.status(400).json({ error: tierError });

    const policy = await prisma.policy.create({
      data: { name, description, conditions, action, severity, channelActions, tiers },
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
    const { name, description, conditions, action, severity, enabled, channelActions, tiers } = req.body;
    const channelError = validateChannelActions(channelActions);
    if (channelError) return res.status(400).json({ error: channelError });
    const tierError = validateTiers(tiers);
    if (tierError) return res.status(400).json({ error: tierError });

    const policy = await prisma.policy.update({
      where: { id: req.params.id },
      data: {
        ...(name !== undefined && { name }),
        ...(description !== undefined && { description }),
        ...(conditions !== undefined && { conditions }),
        ...(action !== undefined && { action }),
        ...(severity !== undefined && { severity }),
        ...(enabled !== undefined && { enabled }),
        ...(channelActions !== undefined && { channelActions }),
        ...(tiers !== undefined && { tiers }),
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
