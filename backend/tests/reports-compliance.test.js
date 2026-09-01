const request = require('supertest');
const app = require('../src/app');
const {
  prisma, resetDb, createUser, authHeader, createAgent, createPolicy,
} = require('./helpers');

afterEach(resetDb);
afterAll(() => prisma.$disconnect());

// The report an auditor asks for, which the daily digest cannot answer:
// "every PCI-DSS event this quarter, and what was done about it."

async function policyFor(rule, overrides = {}) {
  return createPolicy({
    name: `${rule} policy`,
    conditions: { complianceRule: rule },
    action: 'BLOCK',
    severity: 'HIGH',
    ...overrides,
  });
}

async function incident(agent, policy, overrides = {}) {
  return prisma.incident.create({
    data: {
      agentId: agent.id,
      policyId: policy.id,
      channel: 'CLIPBOARD',
      severity: 'HIGH',
      ...overrides,
    },
  });
}

async function attempt(agent, policy, overrides = {}) {
  return prisma.aiLeakAttempt.create({
    data: {
      agentId: agent.id,
      policyId: policy.id,
      platform: 'OPENAI_CHATGPT',
      method: 'CLIPBOARD',
      riskScore: 0.9,
      blocked: true,
      ...overrides,
    },
  });
}

function get(user, qs = '') {
  return request(app).get(`/api/reports/compliance${qs}`).set('Authorization', authHeader(user));
}

describe('GET /api/reports/compliance', () => {
  test('requires authentication', async () => {
    expect((await request(app).get('/api/reports/compliance')).status).toBe(401);
  });

  test('groups events by the compliance rule their policy carries', async () => {
    const { user } = await createUser({ role: 'ADMIN' });
    const agent = await createAgent();
    const pci = await policyFor('PCI-DSS');
    const hipaa = await policyFor('HIPAA');

    await incident(agent, pci);
    await incident(agent, pci);
    await incident(agent, hipaa);

    const res = await get(user);

    expect(res.status).toBe(200);
    const byRule = Object.fromEntries(res.body.rules.map((g) => [g.rule, g]));
    expect(byRule['PCI-DSS'].total).toBe(2);
    expect(byRule.HIPAA.total).toBe(1);
  });

  test('counts incidents and AI leak attempts under the same rule', async () => {
    const { user } = await createUser({ role: 'ADMIN' });
    const agent = await createAgent();
    const pci = await policyFor('PCI-DSS');

    await incident(agent, pci);
    await attempt(agent, pci);

    const res = await get(user);
    const pciGroup = res.body.rules.find((g) => g.rule === 'PCI-DSS');

    expect(pciGroup.total).toBe(2);
    expect(pciGroup.incidents).toBe(1);
    expect(pciGroup.aiLeakAttempts).toBe(1);
  });

  test('lists a rule with a policy but no events, so absence is stated', async () => {
    // "No PCI-DSS incidents this quarter" is a finding an auditor wants to
    // read, not an absent row they have to notice is missing.
    const { user } = await createUser({ role: 'ADMIN' });
    await policyFor('GDPR');

    const res = await get(user);
    const gdpr = res.body.rules.find((g) => g.rule === 'GDPR');

    expect(gdpr).toBeDefined();
    expect(gdpr.total).toBe(0);
  });

  test('flags a rule whose policy is disabled', async () => {
    // A rule with zero events because nothing was watching for it is a very
    // different finding from a rule with zero events because nothing happened.
    const { user } = await createUser({ role: 'ADMIN' });
    await policyFor('HIPAA', { enabled: false });

    const res = await get(user);
    expect(res.body.rules.find((g) => g.rule === 'HIPAA').policyEnabled).toBe(false);
  });

  test('breaks each rule down by severity', async () => {
    const { user } = await createUser({ role: 'ADMIN' });
    const agent = await createAgent();
    const pci = await policyFor('PCI-DSS');

    await incident(agent, pci, { severity: 'CRITICAL' });
    await incident(agent, pci, { severity: 'CRITICAL' });
    await incident(agent, pci, { severity: 'LOW' });

    const res = await get(user);
    const g = res.body.rules.find((x) => x.rule === 'PCI-DSS');

    expect(g.bySeverity.CRITICAL).toBe(2);
    expect(g.bySeverity.LOW).toBe(1);
    expect(g.bySeverity.HIGH).toBe(0);
  });

  test('separates what was stopped from what was only recorded', async () => {
    const { user } = await createUser({ role: 'ADMIN' });
    const agent = await createAgent();
    const blocking = await policyFor('PCI-DSS', { action: 'BLOCK' });
    const alerting = await policyFor('GDPR', { action: 'ALERT' });

    await incident(agent, blocking);
    await incident(agent, alerting);

    const res = await get(user);
    expect(res.body.rules.find((g) => g.rule === 'PCI-DSS').blocked).toBe(1);
    expect(res.body.rules.find((g) => g.rule === 'GDPR').allowed).toBe(1);
  });

  test('surfaces reviews still awaiting an admin decision', async () => {
    const { user } = await createUser({ role: 'ADMIN' });
    const agent = await createAgent();
    const pci = await policyFor('PCI-DSS');

    await incident(agent, pci, { reviewRequested: true });                          // open
    await incident(agent, pci, { reviewRequested: true, adminNote: 'False positive' }); // closed

    const res = await get(user);
    const g = res.body.rules.find((x) => x.rule === 'PCI-DSS');

    expect(g.reviewRequested).toBe(2);
    expect(g.awaitingAdmin).toBe(1);
    expect(res.body.summary.awaitingAdmin).toBe(1);
  });

  test('collects events with no compliance rule under UNCLASSIFIED', async () => {
    const { user } = await createUser({ role: 'ADMIN' });
    const agent = await createAgent();
    const bare = await createPolicy({ conditions: { minRiskScore: 0.5 } });

    await incident(agent, bare);

    const res = await get(user);
    expect(res.body.rules.find((g) => g.rule === 'UNCLASSIFIED').total).toBe(1);
  });

  test('filters to a single rule when asked', async () => {
    const { user } = await createUser({ role: 'ADMIN' });
    const agent = await createAgent();
    await incident(agent, await policyFor('PCI-DSS'));
    await incident(agent, await policyFor('HIPAA'));

    const res = await get(user, '?rule=PCI-DSS');

    expect(res.body.rules).toHaveLength(1);
    expect(res.body.rules[0].rule).toBe('PCI-DSS');
  });

  test('honours the date range', async () => {
    const { user } = await createUser({ role: 'ADMIN' });
    const agent = await createAgent();
    const pci = await policyFor('PCI-DSS');

    await incident(agent, pci, { createdAt: new Date('2026-01-15T10:00:00Z') });
    await incident(agent, pci, { createdAt: new Date('2026-06-15T10:00:00Z') });

    const res = await get(user, '?from=2026-01-01&to=2026-01-31');
    expect(res.body.summary.totalEvents).toBe(1);
  });

  test('includes the `to` day itself', async () => {
    // An auditor asking for 1-31 January means the whole of the 31st.
    const { user } = await createUser({ role: 'ADMIN' });
    const agent = await createAgent();
    const pci = await policyFor('PCI-DSS');
    await incident(agent, pci, { createdAt: new Date('2026-01-31T18:00:00Z') });

    const res = await get(user, '?from=2026-01-01&to=2026-01-31');
    expect(res.body.summary.totalEvents).toBe(1);
  });

  test('rejects an inverted range rather than returning nothing', async () => {
    const { user } = await createUser({ role: 'ADMIN' });
    const res = await get(user, '?from=2026-06-01&to=2026-01-01');
    expect(res.status).toBe(400);
  });

  test('rejects an unparseable date', async () => {
    const { user } = await createUser({ role: 'ADMIN' });
    expect((await get(user, '?from=nonsense')).status).toBe(400);
  });

  test('orders the busiest rule first', async () => {
    const { user } = await createUser({ role: 'ADMIN' });
    const agent = await createAgent();
    const pci = await policyFor('PCI-DSS');
    const hipaa = await policyFor('HIPAA');

    await incident(agent, hipaa);
    await incident(agent, pci);
    await incident(agent, pci);
    await incident(agent, pci);

    const res = await get(user);
    expect(res.body.rules[0].rule).toBe('PCI-DSS');
  });

  test('carries the underlying events for drill-down, newest first', async () => {
    const { user } = await createUser({ role: 'ADMIN' });
    const agent = await createAgent({ hostname: 'FINANCE-WS-01' });
    const pci = await policyFor('PCI-DSS');

    await incident(agent, pci, { createdAt: new Date('2026-01-01T10:00:00Z') });
    await incident(agent, pci, { createdAt: new Date('2026-01-02T10:00:00Z') });

    const res = await get(user, '?from=2025-12-01&to=2026-02-01');
    const g = res.body.rules.find((x) => x.rule === 'PCI-DSS');

    expect(g.events).toHaveLength(2);
    expect(new Date(g.events[0].time) > new Date(g.events[1].time)).toBe(true);
    expect(g.events[0].hostname).toBe('FINANCE-WS-01');
  });

  test('returns an empty but well-formed report when nothing has happened', async () => {
    const { user } = await createUser({ role: 'ADMIN' });
    const res = await get(user);

    expect(res.status).toBe(200);
    expect(res.body.summary.totalEvents).toBe(0);
    expect(Array.isArray(res.body.rules)).toBe(true);
  });
});
