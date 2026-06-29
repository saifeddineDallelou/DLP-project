const express = require('express');
const prisma = require('../lib/prisma');
const { authenticate, requireRole } = require('../middleware/auth');

const router = express.Router();

// ── Baselines ─────────────────────────────────────────────────────────────────

// GET /api/ueba/baseline?userId=<id>   (ADMIN/ANALYST can query any user; others get their own)
router.get('/baseline', authenticate, async (req, res, next) => {
  try {
    const targetId = (req.user.role === 'ADMIN' || req.user.role === 'ANALYST')
      ? (req.query.userId || req.user.sub)
      : req.user.sub;

    const baseline = await prisma.userBehaviorBaseline.findUnique({
      where: { userId: targetId },
      include: { user: { select: { id: true, email: true, role: true } } },
    });

    if (!baseline) return res.status(404).json({ error: 'No baseline found for this user' });
    res.json(baseline);
  } catch (err) {
    next(err);
  }
});

// POST /api/ueba/baseline  — create or replace baseline for a user
router.post('/baseline', authenticate, requireRole('ADMIN', 'ANALYST'), async (req, res, next) => {
  try {
    const {
      userId,
      avgDailyFiles,
      avgDailyVolumeMB,
      avgWorkingHourStart,
      avgWorkingHourEnd,
      avgUsbFrequency,
      riskScore,
    } = req.body;

    if (!userId || avgDailyFiles == null || avgDailyVolumeMB == null) {
      return res.status(400).json({ error: 'userId, avgDailyFiles and avgDailyVolumeMB are required' });
    }

    const baseline = await prisma.userBehaviorBaseline.upsert({
      where: { userId },
      update: {
        avgDailyFiles,
        avgDailyVolumeMB,
        avgWorkingHourStart: avgWorkingHourStart ?? 9,
        avgWorkingHourEnd: avgWorkingHourEnd ?? 18,
        avgUsbFrequency: avgUsbFrequency ?? 0,
        riskScore: riskScore ?? 0,
        lastUpdated: new Date(),
      },
      create: {
        userId,
        avgDailyFiles,
        avgDailyVolumeMB,
        avgWorkingHourStart: avgWorkingHourStart ?? 9,
        avgWorkingHourEnd: avgWorkingHourEnd ?? 18,
        avgUsbFrequency: avgUsbFrequency ?? 0,
        riskScore: riskScore ?? 0,
        lastUpdated: new Date(),
      },
    });

    res.status(201).json(baseline);
  } catch (err) {
    if (err.code === 'P2003') return res.status(404).json({ error: 'User not found' });
    next(err);
  }
});

// ── Events ────────────────────────────────────────────────────────────────────

// GET /api/ueba/events?userId=&eventType=&agentId=&page=&limit=
router.get('/events', authenticate, async (req, res, next) => {
  try {
    const { userId, eventType, agentId, page = 1, limit = 50 } = req.query;
    const where = {};
    if (userId) where.userId = userId;
    if (eventType) where.eventType = eventType;
    if (agentId) where.agentId = agentId;

    const skip = (Number(page) - 1) * Number(limit);
    const take = Number(limit);

    const [events, total] = await prisma.$transaction([
      prisma.behaviorEvent.findMany({
        where,
        include: { agent: { select: { id: true, hostname: true } } },
        orderBy: { timestamp: 'desc' },
        skip,
        take,
      }),
      prisma.behaviorEvent.count({ where }),
    ]);

    res.json({ events, total, page: Number(page), limit: take });
  } catch (err) {
    next(err);
  }
});

// POST /api/ueba/events  — agent posts a new behavior event (agent-token auth OR JWT)
router.post('/events', async (req, res, next) => {
  try {
    const { agentId, userId, eventType, metadata } = req.body;
    if (!agentId || !userId || !eventType) {
      return res.status(400).json({ error: 'agentId, userId and eventType are required' });
    }

    // Accept either JWT Bearer or x-agent-token
    const agentToken = req.headers['x-agent-token'];
    if (agentToken) {
      const agent = await prisma.agent.findUnique({ where: { id: agentId } });
      if (!agent || agent.token !== agentToken) {
        return res.status(401).json({ error: 'Unauthorized' });
      }
    } else {
      // Fall through to JWT — require Authorization header
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

    const event = await prisma.behaviorEvent.create({
      data: { agentId, userId, eventType, metadata: metadata ?? {} },
    });

    res.status(201).json(event);
  } catch (err) {
    if (err.code === 'P2003') return res.status(404).json({ error: 'Agent not found' });
    next(err);
  }
});

// ── Risk score ────────────────────────────────────────────────────────────────

// GET /api/ueba/risk-score/:userId
router.get('/risk-score/:userId', authenticate, async (req, res, next) => {
  try {
    const { userId } = req.params;

    const baseline = await prisma.userBehaviorBaseline.findUnique({ where: { userId } });

    // Count anomalous events in the last 24 h
    const since = new Date(Date.now() - 24 * 60 * 60 * 1000);
    const [afterHours, usbInserts, total24h] = await prisma.$transaction([
      prisma.behaviorEvent.count({ where: { userId, eventType: 'AFTER_HOURS_ACCESS', timestamp: { gte: since } } }),
      prisma.behaviorEvent.count({ where: { userId, eventType: 'USB_INSERT', timestamp: { gte: since } } }),
      prisma.behaviorEvent.count({ where: { userId, timestamp: { gte: since } } }),
    ]);

    const baseScore  = baseline?.riskScore ?? 0;
    const liveScore  = Math.min(baseScore + afterHours * 0.1 + usbInserts * 0.05, 1.0);
    const level      = liveScore >= 0.7 ? 'HIGH' : liveScore >= 0.4 ? 'MEDIUM' : 'LOW';

    res.json({
      userId,
      baselineRiskScore: baseScore,
      liveRiskScore: parseFloat(liveScore.toFixed(3)),
      riskLevel: level,
      last24h: { total: total24h, afterHoursAccess: afterHours, usbInserts },
      baselineExists: !!baseline,
    });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
