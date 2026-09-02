const express = require('express');
const prisma = require('../lib/prisma');
const { authenticate, requireRole } = require('../middleware/auth');
const {
  deviationSignal,
  hoursSignal,
  median,
  combine,
  priorityBoost,
  riskLevel,
  baselineIsMature,
  MIN_ACTIVE_DAYS,
  LEARNING_LEVEL,
  ZERO_BASELINE_FLOORS,
} = require('../lib/ueba-scoring');
const { recomputeBaseline } = require('../lib/baseline');
const { toEvent, forwardAsync } = require('../lib/siem');

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

    // Shared with the background refresh job (lib/baseline-refresh.js) so an
    // automatic refresh produces exactly what this button produces.
    const result = await recomputeBaseline({
      userId,
      days,
      department: req.query.department,
    });

    if (!result) {
      return res.status(404).json({
        error: `No behavior events recorded for this user in the last ${days} day(s) -- nothing to compute a baseline from`,
      });
    }

    const { baseline, computedFrom } = result;
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
          eventCount: computedFrom.eventCount,
          avgDailyFiles: baseline.avgDailyFiles,
          avgDailyVolumeMB: baseline.avgDailyVolumeMB,
        },
      },
    });

    res.json({ ...baseline, computedFrom });
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

    // Behaviour events carry no severity -- they are observations, not
    // violations. Forwarded anyway because a SIEM correlating "large transfer
    // at 02:00" against an incident an hour later is exactly the value of
    // having both in one place.
    forwardAsync(toEvent('BEHAVIOR_EVENT', event, {
      raw: event.metadata ?? null,
    }));

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
      select: { eventType: true, metadata: true, agentId: true },
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

    // Deviations are scored only against a baseline built on enough observed
    // days. Below the threshold the components are left empty rather than
    // computed and ignored: a half-formed baseline produces confident-looking
    // numbers ("86% of activity outside working hours") that describe the
    // sample size, not the person.
    const mature = baselineIsMature(baseline);

    const components = {};
    if (baseline && mature) {
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

    // WHAT the user touched, not just how much. A deviation score cannot tell
    // 500 MB of build artefacts from 500 MB of cardholder data.
    //
    // BehaviorEvent carries userId; Incident carries agentId. There is no
    // direct link, so a user is associated with the incidents raised on the
    // endpoints they were active on in the same window. Honest limitation: on
    // a shared workstation this attributes an incident to whoever else was
    // active there. Correcting it would mean the agent stamping the OS user
    // onto every incident it reports.
    const activeAgentIds = [...new Set(todayEvents.map((e) => e.agentId).filter(Boolean))];

    let findings = [];
    if (activeAgentIds.length > 0) {
      const [incidents, attempts] = await Promise.all([
        prisma.incident.findMany({
          where: { agentId: { in: activeAgentIds }, createdAt: { gte: since } },
          select: { severity: true, policy: { select: { conditions: true } } },
        }),
        prisma.aiLeakAttempt.findMany({
          where: { agentId: { in: activeAgentIds }, timestamp: { gte: since } },
          select: { policy: { select: { severity: true, conditions: true } } },
        }),
      ]);

      findings = [
        ...incidents.map((i) => ({
          severity: i.severity,
          rule: i.policy?.conditions?.complianceRule ?? null,
        })),
        // An AI leak attempt has no severity of its own -- it inherits the
        // severity of the policy it violated. Attempts predating the policyId
        // column have no policy at all and are skipped rather than guessed at.
        ...attempts
          .filter((a) => a.policy)
          .map((a) => ({
            severity: a.policy.severity,
            rule: a.policy.conditions?.complianceRule ?? null,
          })),
      ];
    }

    const priority = priorityBoost(findings);

    // With no usable baseline there is nothing to deviate FROM, so the score
    // falls back to the bonuses alone rather than reporting a confident zero.
    // Those bonuses are ABSOLUTE signals -- a large transfer, a PCI-DSS block
    // -- and stay meaningful during learning precisely because they need no
    // baseline. What is withheld is the deviation judgement, not the facts.
    const liveScore = (baseline && mature)
      ? Math.min(1, deviationScore + eventBonus + priority.boost)
      : Math.min(1, eventBonus + priority.boost);

    res.json({
      userId,
      department: baseline?.department ?? null,
      baselineRiskScore: baseline?.riskScore ?? 0,
      liveRiskScore: parseFloat(liveScore.toFixed(3)),
      riskLevel: (baseline && mature) ? riskLevel(liveScore) : LEARNING_LEVEL,
      // Everything the dashboard needs to say "learning, 4 of 7 days" rather
      // than showing a band it has not earned.
      learning: (baseline && mature) ? null : {
        activeDaysObserved: baseline?.activeDaysObserved ?? 0,
        activeDaysRequired: MIN_ACTIVE_DAYS,
        hasBaseline: Boolean(baseline),
      },
      // The breakdown is the point: an analyst has to be able to see WHICH
      // metric drove the score, not just that it was high.
      deviationScore: parseFloat(deviationScore.toFixed(3)),
      eventBonus: parseFloat(eventBonus.toFixed(3)),
      priorityBoost: parseFloat(priority.boost.toFixed(3)),
      // Which compliance rules drove the boost, so the dashboard can say
      // "PCI-DSS, HIPAA" rather than showing an unexplained number.
      priorityRules: priority.rules,
      prioritySeverities: priority.bySeverity,
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
