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

// GET /api/reports/compliance?from=YYYY-MM-DD&to=YYYY-MM-DD&rule=PCI-DSS
//
// Groups a period's incidents and AI leak attempts by the COMPLIANCE RULE
// they violated, rather than by channel or severity.
//
// This is the report an auditor asks for and the daily digest cannot answer:
// "show me every PCI-DSS event this quarter, and what was done about it."
// The data needed already existed -- the classifier tags every detection with
// a compliance rule, and the resolved Policy carries the same vocabulary in
// conditions.complianceRule -- it was simply never grouped that way.
router.get('/compliance', authenticate, async (req, res, next) => {
  try {
    const { from, to, rule } = req.query;

    // Default to the last 30 days rather than erroring: an auditor opening the
    // page should see something, not a validation message.
    const end = to ? new Date(`${to}T00:00:00`) : new Date();
    if (to) end.setDate(end.getDate() + 1);           // inclusive of `to`
    const start = from
      ? new Date(`${from}T00:00:00`)
      : new Date(end.getTime() - 30 * 24 * 60 * 60 * 1000);

    if (isNaN(start) || isNaN(end)) {
      return res.status(400).json({ error: 'from and to must be YYYY-MM-DD' });
    }
    if (start >= end) {
      return res.status(400).json({ error: 'from must be earlier than to' });
    }

    const [incidents, attempts, policies] = await Promise.all([
      prisma.incident.findMany({
        where: { createdAt: { gte: start, lt: end } },
        include: {
          policy: { select: { id: true, name: true, conditions: true, action: true } },
          agent: { select: { hostname: true } },
        },
        orderBy: { createdAt: 'desc' },
      }),
      prisma.aiLeakAttempt.findMany({
        where: { timestamp: { gte: start, lt: end } },
        include: {
          policy: { select: { id: true, name: true, conditions: true, action: true } },
          agent: { select: { hostname: true } },
        },
        orderBy: { timestamp: 'desc' },
      }),
      // Every rule the deployment has a policy for, so a rule with zero
      // events still appears. "No PCI-DSS incidents this quarter" is a
      // finding an auditor wants stated, not an absent row they have to
      // notice is missing.
      prisma.policy.findMany({ select: { conditions: true, enabled: true } }),
    ]);

    const ruleOf = (row) => row.policy?.conditions?.complianceRule ?? 'UNCLASSIFIED';

    const groups = new Map();
    const ensure = (name) => {
      if (!groups.has(name)) {
        groups.set(name, {
          rule: name,
          total: 0,
          incidents: 0,
          aiLeakAttempts: 0,
          blocked: 0,
          allowed: 0,
          bySeverity: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 },
          reviewRequested: 0,
          awaitingAdmin: 0,
          policyEnabled: true,
          events: [],
        });
      }
      return groups.get(name);
    };

    for (const p of policies) {
      const name = p.conditions?.complianceRule;
      if (name) {
        const g = ensure(name);
        // A rule is only "covered" if at least one policy for it is enabled.
        g.policyEnabled = g.policyEnabled && p.enabled;
      }
    }

    for (const i of incidents) {
      const g = ensure(ruleOf(i));
      g.total += 1;
      g.incidents += 1;
      if (i.severity && g.bySeverity[i.severity] != null) g.bySeverity[i.severity] += 1;
      if (i.reviewRequested) g.reviewRequested += 1;
      if (i.reviewRequested && !i.adminNote) g.awaitingAdmin += 1;
      // An incident records a detection, not a transmission -- the policy
      // action is what says whether anything was stopped.
      if (i.policy?.action === 'BLOCK' || i.policy?.action === 'QUARANTINE') g.blocked += 1;
      else g.allowed += 1;
      g.events.push({
        kind: 'INCIDENT',
        id: i.id,
        time: i.createdAt,
        severity: i.severity,
        channel: i.channel,
        status: i.status,
        hostname: i.agent?.hostname ?? null,
        policyName: i.policy?.name ?? null,
        riskScore: i.riskScore,
        reviewRequested: i.reviewRequested,
        adminNote: i.adminNote,
      });
    }

    for (const a of attempts) {
      const g = ensure(ruleOf(a));
      g.total += 1;
      g.aiLeakAttempts += 1;
      if (a.blocked) g.blocked += 1; else g.allowed += 1;
      if (a.reviewRequested) g.reviewRequested += 1;
      if (a.reviewRequested && !a.adminNote) g.awaitingAdmin += 1;
      g.events.push({
        kind: 'AI_LEAK_ATTEMPT',
        id: a.id,
        time: a.timestamp,
        severity: null,
        channel: a.platform,
        status: a.blocked ? 'BLOCKED' : 'ALLOWED',
        hostname: a.agent?.hostname ?? null,
        policyName: a.policy?.name ?? null,
        riskScore: a.riskScore,
        reviewRequested: a.reviewRequested,
        adminNote: a.adminNote,
      });
    }

    let result = [...groups.values()];
    if (rule) result = result.filter((g) => g.rule === rule);

    for (const g of result) {
      g.events.sort((x, y) => new Date(y.time) - new Date(x.time));
    }
    // Busiest rule first -- that is where an auditor's attention should go.
    result.sort((a, b) => b.total - a.total || a.rule.localeCompare(b.rule));

    res.json({
      period: { from: start.toISOString(), to: end.toISOString() },
      summary: {
        totalEvents: incidents.length + attempts.length,
        totalIncidents: incidents.length,
        totalAiLeakAttempts: attempts.length,
        rulesWithActivity: result.filter((g) => g.total > 0).length,
        rulesCovered: result.length,
        awaitingAdmin: result.reduce((n, g) => n + g.awaitingAdmin, 0),
      },
      rules: result,
    });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
