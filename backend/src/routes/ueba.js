const express = require('express');
const prisma = require('../lib/prisma');
const { authenticate, requireRole } = require('../middleware/auth');
const {
  deviationSignal,
  hoursSignal,
  median,
  combine,
  riskLevel,
  ZERO_BASELINE_FLOORS,
} = require('../lib/ueba-scoring');

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
      department,
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
        // undefined leaves the stored department alone; an explicit null
        // clears it. Omitting the field from a numbers-only edit should not
        // drop the user out of peer scoring.
        ...(department !== undefined ? { department } : {}),
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
        department: department ?? null,
        avgDailyFiles,
        avgDailyVolumeMB,
        avgWorkingHourStart: avgWorkingHourStart ?? 9,
        avgWorkingHourEnd: avgWorkingHourEnd ?? 18,
        avgUsbFrequency: avgUsbFrequency ?? 0,
        riskScore: riskScore ?? 0,
        lastUpdated: new Date(),
      },
    });

    // Changing a baseline redefines what counts as "normal" for this user, and
    // therefore what will and will not raise their risk score in future. A
    // manually entered baseline is the one way to make anomalous behaviour
    // look unremarkable, so it needs a record of who set it.
    await prisma.auditLog.create({
      data: {
        userId: req.user.sub,
        action: 'SET_BEHAVIOR_BASELINE',
        resource: 'user_behavior_baseline',
        resourceId: baseline.id,
        ipAddress: req.ip,
        metadata: {
          monitoredUserId: userId,
          source: 'MANUAL',
          avgDailyFiles: baseline.avgDailyFiles,
          avgDailyVolumeMB: baseline.avgDailyVolumeMB,
        },
      },
    });

    res.status(201).json(baseline);
  } catch (err) {
    next(err);
  }
});

// POST /api/ueba/baseline/:userId/recompute?days=30 — compute a baseline
// from this user's actual BehaviorEvent history instead of accepting
// arbitrary values in the request body (that's what POST /baseline is for --
// this endpoint replaces the numbers with ones derived from real behavior).
router.post('/baseline/:userId/recompute', authenticate, requireRole('ADMIN', 'ANALYST'), async (req, res, next) => {
  try {
    const { userId } = req.params;
    const days = Math.max(1, Number(req.query.days) || 30);
    const since = new Date(Date.now() - days * 24 * 60 * 60 * 1000);

    const events = await prisma.behaviorEvent.findMany({
      where: { userId, timestamp: { gte: since } },
      select: { eventType: true, metadata: true, timestamp: true },
    });

    if (events.length === 0) {
      return res.status(404).json({
        error: `No behavior events recorded for this user in the last ${days} day(s) -- nothing to compute a baseline from`,
      });
    }

    // Bucket per calendar day, so the baseline can be a median across days
    // rather than a mean. The working-hours bounds were already outlier-
    // resistant (10th/90th percentile, see below); file count and volume were
    // not -- they were sum/days, so one 8 GB afternoon shifted the number every
    // subsequent day would be judged against. A median ignores that day
    // entirely, which is the same protection the hours already had.
    const perDay = new Map();
    const dayKey = (d) => new Date(d).toISOString().slice(0, 10);

    let usbInserts = 0;
    let largeFileTransfers = 0;
    const hours = [];

    for (const e of events) {
      const key = dayKey(e.timestamp);
      if (!perDay.has(key)) perDay.set(key, { files: 0, volumeMB: 0, usb: 0 });
      const day = perDay.get(key);

      if (e.eventType === 'FILE_ACCESS' || e.eventType === 'AFTER_HOURS_ACCESS') {
        day.files += Number(e.metadata?.count) || 0;
        day.volumeMB += Number(e.metadata?.sizeMB) || 0;
        if (typeof e.metadata?.hour === 'number') hours.push(e.metadata.hour);
      } else if (e.eventType === 'USB_INSERT') {
        day.usb += 1;
        usbInserts += 1;
      } else if (e.eventType === 'LARGE_FILE_TRANSFER') {
        // Its own event, on top of (not part of) FILE_ACCESS/
        // AFTER_HOURS_ACCESS -- a file over the large-file threshold is
        // excluded from the routine content-scan path entirely (see
        // agent/src/file_watcher.py), so its volume is never double-counted.
        day.volumeMB += Number(e.metadata?.sizeMB) || 0;
        largeFileTransfers += 1;
      }
    }

    // Median across ACTIVE days only -- days the user generated no events at
    // all are excluded rather than counted as zero. The question the baseline
    // answers is "on a day this person is working, what is typical", and
    // padding with weekends and leave would drag every baseline toward zero
    // and make ordinary Monday activity look anomalous.
    const activeDays = [...perDay.values()];
    const medianFiles = median(activeDays.map((d) => d.files));
    const medianVolume = median(activeDays.map((d) => d.volumeMB));
    const medianUsb = median(activeDays.map((d) => d.usb));

    hours.sort((a, b) => a - b);
    // 10th/90th percentile rather than min/max -- a couple of one-off late
    // nights shouldn't redefine this user's whole "working hours" baseline.
    const percentile = (p) => hours.length ? hours[Math.floor(p * (hours.length - 1))] : null;
    const round2 = (n) => Math.round(n * 100) / 100;

    const existing = await prisma.userBehaviorBaseline.findUnique({ where: { userId } });
    // Only overwrite the declared department when the caller actually supplies
    // one -- a recompute is about the numbers, and silently clearing a peer
    // group as a side effect would drop the user out of peer scoring.
    const department = req.query.department ?? existing?.department ?? null;

    const baseline = await prisma.userBehaviorBaseline.upsert({
      where: { userId },
      update: {
        department,
        avgDailyFiles: round2(medianFiles),
        avgDailyVolumeMB: round2(medianVolume),
        avgWorkingHourStart: percentile(0.1) ?? existing?.avgWorkingHourStart ?? 9,
        avgWorkingHourEnd: percentile(0.9) ?? existing?.avgWorkingHourEnd ?? 18,
        avgUsbFrequency: round2(medianUsb),
        lastUpdated: new Date(),
      },
      create: {
        userId,
        department,
        avgDailyFiles: round2(medianFiles),
        avgDailyVolumeMB: round2(medianVolume),
        avgWorkingHourStart: percentile(0.1) ?? 9,
        avgWorkingHourEnd: percentile(0.9) ?? 18,
        avgUsbFrequency: round2(medianUsb),
        riskScore: 0,
        lastUpdated: new Date(),
      },
    });

    // Audited like the manual path above. A recompute is derived from real
    // event history rather than typed in, but it still overwrites the numbers
    // every future risk score is measured against -- and the window (`days`)
    // is caller-chosen, so a deliberately narrow window can still be used to
    // reshape a baseline. The metadata records what it was derived from.
    await prisma.auditLog.create({
      data: {
        userId: req.user.sub,
        action: 'RECOMPUTE_BEHAVIOR_BASELINE',
        resource: 'user_behavior_baseline',
        resourceId: baseline.id,
        ipAddress: req.ip,
        metadata: {
          monitoredUserId: userId,
          source: 'RECOMPUTED',
          days,
          eventCount: events.length,
          avgDailyFiles: baseline.avgDailyFiles,
          avgDailyVolumeMB: baseline.avgDailyVolumeMB,
        },
      },
    });

    res.json({
      ...baseline,
      computedFrom: {
        eventCount: events.length,
        days,
        activeDays: activeDays.length,
        largeFileTransfers,
        usbInserts,
        // Named so the response says plainly what statistic produced these
        // numbers -- a caller comparing two baselines needs to know one is a
        // median across active days, not a mean across the whole window.
        statistic: 'median-across-active-days',
      },
    });
  } catch (err) {
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
    const [afterHours, usbInserts, largeFileTransfers, total24h] = await prisma.$transaction([
      prisma.behaviorEvent.count({ where: { userId, eventType: 'AFTER_HOURS_ACCESS', timestamp: { gte: since } } }),
      prisma.behaviorEvent.count({ where: { userId, eventType: 'USB_INSERT', timestamp: { gte: since } } }),
      prisma.behaviorEvent.count({ where: { userId, eventType: 'LARGE_FILE_TRANSFER', timestamp: { gte: since } } }),
      prisma.behaviorEvent.count({ where: { userId, timestamp: { gte: since } } }),
    ]);

    // What the user ACTUALLY did in the last 24 h, in the same units the
    // baseline is expressed in. Without this the baseline could never be
    // compared against anything -- which was the bug: avgDailyFiles and
    // avgDailyVolumeMB were computed, displayed, and never read.
    const todayEvents = await prisma.behaviorEvent.findMany({
      where: { userId, timestamp: { gte: since } },
      select: { eventType: true, metadata: true },
    });

    let todayFiles = 0;
    let todayVolumeMB = 0;
    const todayHours = [];

    for (const e of todayEvents) {
      if (e.eventType === 'FILE_ACCESS' || e.eventType === 'AFTER_HOURS_ACCESS') {
        todayFiles += Number(e.metadata?.count) || 0;
        todayVolumeMB += Number(e.metadata?.sizeMB) || 0;
      } else if (e.eventType === 'LARGE_FILE_TRANSFER') {
        todayVolumeMB += Number(e.metadata?.sizeMB) || 0;
      }
      if (typeof e.metadata?.hour === 'number') todayHours.push(e.metadata.hour);
    }

    // Peer medians, when the user has a declared department. Computed from the
    // OTHER members' baselines -- including the user's own would let a single
    // outlier partly define the group they are being compared against.
    let peers = [];
    if (baseline?.department) {
      peers = await prisma.userBehaviorBaseline.findMany({
        where: { department: baseline.department, userId: { not: userId } },
        select: { avgDailyFiles: true, avgDailyVolumeMB: true, avgUsbFrequency: true },
      });
    }
    const hasPeers = peers.length > 0;
    const peerMedians = hasPeers ? {
      files: median(peers.map((p) => p.avgDailyFiles)),
      volumeMB: median(peers.map((p) => p.avgDailyVolumeMB)),
      usb: median(peers.map((p) => p.avgUsbFrequency)),
    } : null;

    const components = {};
    if (baseline) {
      const vol = deviationSignal(todayVolumeMB, baseline.avgDailyVolumeMB, ZERO_BASELINE_FLOORS.volumeMB);
      const fil = deviationSignal(todayFiles, baseline.avgDailyFiles, ZERO_BASELINE_FLOORS.files);
      const usb = deviationSignal(usbInserts, baseline.avgUsbFrequency, ZERO_BASELINE_FLOORS.usb);
      const hrs = hoursSignal(todayHours, baseline.avgWorkingHourStart, baseline.avgWorkingHourEnd);

      const peerVol = hasPeers ? deviationSignal(todayVolumeMB, peerMedians.volumeMB, ZERO_BASELINE_FLOORS.volumeMB) : null;
      const peerFil = hasPeers ? deviationSignal(todayFiles, peerMedians.files, ZERO_BASELINE_FLOORS.files) : null;
      const peerUsb = hasPeers ? deviationSignal(usbInserts, peerMedians.usb, ZERO_BASELINE_FLOORS.usb) : null;

      components.volume = {
        observed: Math.round(todayVolumeMB * 100) / 100,
        baseline: baseline.avgDailyVolumeMB,
        ratio: vol.ratio,
        signal: vol.signal,
        peerBaseline: hasPeers ? peerMedians.volumeMB : null,
        peerRatio: peerVol?.ratio ?? null,
        peerSignal: peerVol?.signal ?? null,
      };
      components.files = {
        observed: todayFiles,
        baseline: baseline.avgDailyFiles,
        ratio: fil.ratio,
        signal: fil.signal,
        peerBaseline: hasPeers ? peerMedians.files : null,
        peerRatio: peerFil?.ratio ?? null,
        peerSignal: peerFil?.signal ?? null,
      };
      components.hours = {
        observed: hrs.outside,
        total: hrs.total,
        baseline: `${baseline.avgWorkingHourStart}-${baseline.avgWorkingHourEnd}`,
        ratio: null,
        signal: hrs.signal,
        peerSignal: null,
      };
      components.usb = {
        observed: usbInserts,
        baseline: baseline.avgUsbFrequency,
        ratio: usb.ratio,
        signal: usb.signal,
        peerBaseline: hasPeers ? peerMedians.usb : null,
        peerRatio: peerUsb?.ratio ?? null,
        peerSignal: peerUsb?.signal ?? null,
      };
    }

    const deviationScore = combine(components);

    // Event-type bonuses are kept, at reduced weight. They carry information
    // deviation does not: a LARGE_FILE_TRANSFER is categorically interesting
    // even at volumes within this user's normal range. They are no longer the
    // whole score, which is what they were before.
    const eventBonus = Math.min(
      0.3,
      afterHours * 0.05 + usbInserts * 0.02 + largeFileTransfers * 0.08,
    );

    // With no baseline there is nothing to deviate FROM, so the score falls
    // back to the event bonuses alone rather than reporting a confident zero.
    const liveScore = baseline
      ? Math.min(1, deviationScore + eventBonus)
      : Math.min(1, eventBonus);

    res.json({
      userId,
      department: baseline?.department ?? null,
      baselineRiskScore: baseline?.riskScore ?? 0,
      liveRiskScore: parseFloat(liveScore.toFixed(3)),
      riskLevel: riskLevel(liveScore),
      // The breakdown is the point: an analyst has to be able to see WHICH
      // metric drove the score, not just that it was high.
      deviationScore: parseFloat(deviationScore.toFixed(3)),
      eventBonus: parseFloat(eventBonus.toFixed(3)),
      components,
      peerGroup: baseline?.department
        ? { department: baseline.department, peerCount: peers.length }
        : null,
      last24h: {
        total: total24h,
        afterHoursAccess: afterHours,
        usbInserts,
        largeFileTransfers,
        files: todayFiles,
        volumeMB: Math.round(todayVolumeMB * 100) / 100,
      },
      baselineExists: !!baseline,
      baseline: baseline ? {
        department: baseline.department,
        avgDailyFiles: baseline.avgDailyFiles,
        avgDailyVolumeMB: baseline.avgDailyVolumeMB,
        avgWorkingHourStart: baseline.avgWorkingHourStart,
        avgWorkingHourEnd: baseline.avgWorkingHourEnd,
        avgUsbFrequency: baseline.avgUsbFrequency,
        lastUpdated: baseline.lastUpdated,
      } : null,
    });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
