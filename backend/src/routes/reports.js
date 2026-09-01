const express = require('express');
const prisma = require('../lib/prisma');
const { authenticate } = require('../middleware/auth');

const router = express.Router();

function dayBounds(dateStr) {
  // dateStr is "YYYY-MM-DD" in the server's local time; treated as a plain
  // calendar day, not a specific timezone offset -- fine for a single-admin
  // small-deployment report, not built for multi-timezone rollups.
  const start = new Date(`${dateStr}T00:00:00`);
  const end = new Date(`${dateStr}T00:00:00`);
  end.setDate(end.getDate() + 1);
  return { start, end };
}

// GET /api/reports/daily?date=YYYY-MM-DD  (defaults to today)
// Merges Incidents and AiLeakAttempts for the day into one chronological
// timeline -- this is the "what happened today" digest an admin reads once
// at end of day, distinct from the Incidents/AiPolicy tables which are for
// ongoing case-by-case triage.
router.get('/daily', authenticate, async (req, res, next) => {
  try {
    const dateStr = req.query.date || new Date().toISOString().slice(0, 10);
    if (!/^\d{4}-\d{2}-\d{2}$/.test(dateStr)) {
      return res.status(400).json({ error: 'date must be YYYY-MM-DD' });
    }
    const { start, end } = dayBounds(dateStr);

    const [incidents, attempts] = await Promise.all([
      prisma.incident.findMany({
        where: { createdAt: { gte: start, lt: end } },
        include: {
          agent: { select: { id: true, hostname: true } },
          policy: { select: { id: true, name: true, action: true } },
          assignedTo: { select: { id: true, email: true } },
        },
        orderBy: { createdAt: 'asc' },
      }),
      prisma.aiLeakAttempt.findMany({
        where: { timestamp: { gte: start, lt: end } },
        include: {
          agent: { select: { id: true, hostname: true } },
          policy: { select: { id: true, name: true, action: true } },
        },
        orderBy: { timestamp: 'asc' },
      }),
    ]);

    const timeline = [
      ...incidents.map(i => ({
        kind: 'INCIDENT',
        id: i.id,
        time: i.createdAt,
        severity: i.severity,
        channel: i.channel,
        status: i.status,
        agent: i.agent,
        policy: i.policy,
        reviewRequested: i.reviewRequested,
        justification: i.justification,
        adminNote: i.adminNote,
      })),
      ...attempts.map(a => ({
        kind: 'AI_LEAK_ATTEMPT',
        id: a.id,
        time: a.timestamp,
        severity: null,
        channel: a.platform,
        status: a.blocked ? 'BLOCKED' : 'ALLOWED',
        agent: a.agent,
        policy: a.policy,
        reviewRequested: a.reviewRequested,
        justification: a.justification,
        adminNote: a.adminNote,
      })),
    ].sort((x, y) => new Date(x.time) - new Date(y.time));

    res.json({
      date: dateStr,
      summary: {
        totalIncidents: incidents.length,
        totalAiLeakAttempts: attempts.length,
        reviewRequested: timeline.filter(t => t.reviewRequested).length,
        needsAdminNote: timeline.filter(t => t.reviewRequested && !t.adminNote).length,
      },
      timeline,
    });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
