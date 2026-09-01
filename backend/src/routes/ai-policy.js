const express = require('express');
const prisma = require('../lib/prisma');
const { authenticate, requireRole } = require('../middleware/auth');
const { toEvent, forwardAsync } = require('../lib/siem');

const router = express.Router();

// ── Single attempt (agent-facing) ─────────────────────────────────────────────

// GET /api/ai-policy/attempt?agentId=  — latest attempt for an agent (quick check)
router.get('/attempt', authenticate, async (req, res, next) => {
  try {
    const { agentId } = req.query;
    const where = agentId ? { agentId } : {};

    const attempt = await prisma.aiLeakAttempt.findFirst({
      where,
      include: {
        agent: { select: { id: true, hostname: true } },
        policy: { select: { id: true, name: true, action: true } },
      },
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
    const { agentId, policyId, platform, method, contentSample, riskScore, blocked } = req.body;

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

    const attemptData = {
      agentId,
      policyId: policyId ?? null,
      platform,
      method,
      contentSample: contentSample ?? null,
      riskScore,
      blocked: blocked ?? true,
    };

    let attempt;
    try {
      attempt = await prisma.aiLeakAttempt.create({ data: attemptData });
    } catch (err) {
      // agentId is already verified above when using x-agent-token, so a
      // P2003 here can only be an unrecognised policyId (e.g. the agent's
      // PolicyResolver default pointing at a policy id this DB was never
      // seeded with) -- don't drop the leak-attempt record over that,
      // just record it without the policy link.
      if (err.code === 'P2003' && agentToken && policyId) {
        attempt = await prisma.aiLeakAttempt.create({ data: { ...attemptData, policyId: null } });
      } else {
        throw err;
      }
    }

    // An AI leak attempt has no severity of its own -- it inherits the
    // severity of the policy it violated, so the SIEM's own alert rules key
    // off something meaningful rather than every attempt arriving unranked.
    const context = attempt.policyId
      ? await prisma.policy.findUnique({
          where: { id: attempt.policyId },
          select: { name: true, severity: true, action: true, conditions: true },
        })
      : null;
    const agentRow = await prisma.agent.findUnique({
      where: { id: attempt.agentId },
      select: { hostname: true },
    });

    forwardAsync(toEvent('AI_LEAK_ATTEMPT', attempt, {
      hostname: agentRow?.hostname ?? null,
      severity: context?.severity ?? null,
      policyName: context?.name ?? null,
      action: context?.action ?? null,
      complianceRule: context?.conditions?.complianceRule ?? null,
      raw: { platform: attempt.platform, method: attempt.method },
    }));

    res.status(201).json(attempt);
  } catch (err) {
    if (err.code === 'P2003') return res.status(404).json({ error: 'Agent or policy not found' });
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
        include: {
          agent: { select: { id: true, hostname: true, os: true } },
          policy: { select: { id: true, name: true, action: true } },
        },
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

// PATCH /api/ai-policy/attempt/:id/request-review  (agent-token only -- the
// block is silent for the end user; this just flags it with an optional note
// asking an admin to take a look. Never unblocks/restores anything itself.)
router.patch('/attempt/:id/request-review', async (req, res, next) => {
  try {
    const agentToken = req.headers['x-agent-token'];
    if (!agentToken) return res.status(401).json({ error: 'x-agent-token required' });

    const { note } = req.body;

    const attempt = await prisma.aiLeakAttempt.findUnique({ where: { id: req.params.id } });
    if (!attempt) return res.status(404).json({ error: 'Attempt not found' });

    const agent = await prisma.agent.findUnique({ where: { id: attempt.agentId } });
    if (!agent || agent.token !== agentToken) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    const updated = await prisma.aiLeakAttempt.update({
      where: { id: req.params.id },
      data: { reviewRequested: true, justification: note && note.trim() ? note.trim() : null },
    });

    res.json(updated);
  } catch (err) {
    next(err);
  }
});

// PATCH /api/ai-policy/attempt/:id  (admin/analyst-facing -- record the
// admin's explanation after reviewing an attempt)
router.patch('/attempt/:id', authenticate, requireRole('ADMIN', 'ANALYST'), async (req, res, next) => {
  try {
    const { adminNote } = req.body;
    const data = {};
    if (adminNote !== undefined) data.adminNote = adminNote;

    const attempt = await prisma.aiLeakAttempt.update({ where: { id: req.params.id }, data });

    // Adjudicating a blocked leak is one of the most consequential actions in
    // the system -- it is an admin recording a disposition on an attempt the
    // agent already blocked. It was previously the only role-guarded write
    // that left no trace.
    await prisma.auditLog.create({
      data: {
        userId: req.user.sub,
        action: 'ADJUDICATE_AI_LEAK_ATTEMPT',
        resource: 'ai_leak_attempt',
        resourceId: attempt.id,
        ipAddress: req.ip,
        metadata: {
          platform: attempt.platform,
          reviewRequested: attempt.reviewRequested,
          adminNote: adminNote ?? null,
        },
      },
    });

    res.json(attempt);
  } catch (err) {
    if (err.code === 'P2025') return res.status(404).json({ error: 'Attempt not found' });
    next(err);
  }
});

module.exports = router;
