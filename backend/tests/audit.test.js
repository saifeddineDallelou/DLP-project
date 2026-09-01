const request = require('supertest');
const app = require('../src/app');
const {
  prisma,
  resetDb,
  createUser,
  authHeader,
  createAgent,
  createPolicy,
} = require('./helpers');

afterEach(resetDb);
afterAll(() => prisma.$disconnect());

async function seedLog(userId, overrides = {}) {
  return prisma.auditLog.create({
    data: {
      userId,
      action: overrides.action || 'UPDATE_POLICY',
      resource: overrides.resource || 'policy',
      resourceId: overrides.resourceId || 'res-1',
      ipAddress: overrides.ipAddress || '127.0.0.1',
      metadata: overrides.metadata ?? {},
      ...(overrides.createdAt ? { createdAt: overrides.createdAt } : {}),
    },
  });
}

describe('GET /api/audit', () => {
  test('requires authentication', async () => {
    const res = await request(app).get('/api/audit');
    expect(res.status).toBe(401);
  });

  test('rejects a VIEWER role', async () => {
    const { user } = await createUser({ role: 'VIEWER' });
    const res = await request(app).get('/api/audit').set('Authorization', authHeader(user));
    expect(res.status).toBe(403);
  });

  test('allows ANALYST and ADMIN', async () => {
    const { user: analyst } = await createUser({ role: 'ANALYST' });
    const { user: admin } = await createUser({ role: 'ADMIN' });

    for (const u of [analyst, admin]) {
      const res = await request(app).get('/api/audit').set('Authorization', authHeader(u));
      expect(res.status).toBe(200);
    }
  });

  test('returns logs newest first with the acting user joined', async () => {
    const { user } = await createUser({ role: 'ADMIN' });
    await seedLog(user.id, { action: 'CREATE_POLICY', createdAt: new Date('2026-01-01T10:00:00Z') });
    await seedLog(user.id, { action: 'DELETE_POLICY', createdAt: new Date('2026-01-02T10:00:00Z') });

    const res = await request(app).get('/api/audit').set('Authorization', authHeader(user));

    expect(res.status).toBe(200);
    expect(res.body.total).toBe(2);
    expect(res.body.logs[0].action).toBe('DELETE_POLICY');
    expect(res.body.logs[0].user.email).toBe(user.email);
  });

  test('filters by resource, action and userId', async () => {
    const { user: a } = await createUser({ role: 'ADMIN' });
    const { user: b } = await createUser({ role: 'ADMIN' });
    await seedLog(a.id, { action: 'CREATE_POLICY', resource: 'policy' });
    await seedLog(a.id, { action: 'DELETE_AGENT', resource: 'agent' });
    await seedLog(b.id, { action: 'CREATE_POLICY', resource: 'policy' });

    const byResource = await request(app)
      .get('/api/audit?resource=agent').set('Authorization', authHeader(a));
    expect(byResource.body.total).toBe(1);

    const byAction = await request(app)
      .get('/api/audit?action=CREATE_POLICY').set('Authorization', authHeader(a));
    expect(byAction.body.total).toBe(2);

    const byUser = await request(app)
      .get(`/api/audit?userId=${b.id}`).set('Authorization', authHeader(a));
    expect(byUser.body.total).toBe(1);
  });

  test('filters by date range', async () => {
    const { user } = await createUser({ role: 'ADMIN' });
    await seedLog(user.id, { createdAt: new Date('2026-01-01T10:00:00Z') });
    await seedLog(user.id, { createdAt: new Date('2026-06-01T10:00:00Z') });

    const res = await request(app)
      .get('/api/audit?from=2026-05-01&to=2026-07-01')
      .set('Authorization', authHeader(user));

    expect(res.body.total).toBe(1);
  });

  test('rejects an unparseable date', async () => {
    const { user } = await createUser({ role: 'ADMIN' });
    const res = await request(app)
      .get('/api/audit?from=not-a-date').set('Authorization', authHeader(user));
    expect(res.status).toBe(400);
  });

  test('paginates and caps limit at 200', async () => {
    const { user } = await createUser({ role: 'ADMIN' });
    for (let i = 0; i < 5; i++) await seedLog(user.id);

    const page1 = await request(app)
      .get('/api/audit?page=1&limit=2').set('Authorization', authHeader(user));
    expect(page1.body.logs).toHaveLength(2);
    expect(page1.body.pages).toBe(3);

    const capped = await request(app)
      .get('/api/audit?limit=9999').set('Authorization', authHeader(user));
    expect(capped.body.limit).toBe(200);
  });
});

describe('GET /api/audit/actions', () => {
  test('returns the distinct actions and resources present', async () => {
    const { user } = await createUser({ role: 'ADMIN' });
    await seedLog(user.id, { action: 'CREATE_POLICY', resource: 'policy' });
    await seedLog(user.id, { action: 'CREATE_POLICY', resource: 'policy' });
    await seedLog(user.id, { action: 'DELETE_AGENT', resource: 'agent' });

    const res = await request(app).get('/api/audit/actions').set('Authorization', authHeader(user));

    expect(res.status).toBe(200);
    expect(res.body.actions).toEqual(['CREATE_POLICY', 'DELETE_AGENT']);
    expect(res.body.resources).toEqual(['agent', 'policy']);
  });
});

describe('GET /api/audit/resource/:resource/:resourceId', () => {
  test('returns every action against one object', async () => {
    const { user } = await createUser({ role: 'ADMIN' });
    await seedLog(user.id, { resource: 'incident', resourceId: 'inc-1', action: 'UPDATE_INCIDENT' });
    await seedLog(user.id, { resource: 'incident', resourceId: 'inc-1', action: 'ASSIGN_INCIDENT' });
    await seedLog(user.id, { resource: 'incident', resourceId: 'inc-2', action: 'UPDATE_INCIDENT' });

    const res = await request(app)
      .get('/api/audit/resource/incident/inc-1').set('Authorization', authHeader(user));

    expect(res.status).toBe(200);
    expect(res.body.logs).toHaveLength(2);
  });

  test('returns an empty list for an object with no history', async () => {
    const { user } = await createUser({ role: 'ADMIN' });
    const res = await request(app)
      .get('/api/audit/resource/incident/nope').set('Authorization', authHeader(user));
    expect(res.status).toBe(200);
    expect(res.body.logs).toEqual([]);
  });
});

// The point of this batch: these four admin actions were role-guarded but left
// no trace. Each test asserts the action is now recorded, not just that the
// endpoint still works.
describe('audit coverage for previously unlogged admin actions', () => {
  test('adjudicating an AI leak attempt is recorded', async () => {
    const { user } = await createUser({ role: 'ADMIN' });
    const agent = await createAgent();
    const attempt = await prisma.aiLeakAttempt.create({
      data: { agentId: agent.id, platform: 'OPENAI_CHATGPT', method: 'CLIPBOARD', riskScore: 0.9 },
    });

    const res = await request(app)
      .patch(`/api/ai-policy/attempt/${attempt.id}`)
      .set('Authorization', authHeader(user))
      .send({ adminNote: 'Confirmed exfiltration attempt' });

    expect(res.status).toBe(200);

    const logs = await prisma.auditLog.findMany({ where: { action: 'ADJUDICATE_AI_LEAK_ATTEMPT' } });
    expect(logs).toHaveLength(1);
    expect(logs[0].userId).toBe(user.id);
    expect(logs[0].resourceId).toBe(attempt.id);
    expect(logs[0].metadata.adminNote).toBe('Confirmed exfiltration attempt');
  });

  test('setting a behavior baseline manually is recorded', async () => {
    const { user } = await createUser({ role: 'ADMIN' });

    const res = await request(app)
      .post('/api/ueba/baseline')
      .set('Authorization', authHeader(user))
      .send({ userId: 'WORKSTATION\\jdoe', avgDailyFiles: 10, avgDailyVolumeMB: 50 });

    expect(res.status).toBe(201);

    const logs = await prisma.auditLog.findMany({ where: { action: 'SET_BEHAVIOR_BASELINE' } });
    expect(logs).toHaveLength(1);
    expect(logs[0].metadata.source).toBe('MANUAL');
    expect(logs[0].metadata.monitoredUserId).toBe('WORKSTATION\\jdoe');
  });

  test('recomputing a behavior baseline is recorded with its window', async () => {
    const { user } = await createUser({ role: 'ADMIN' });
    const agent = await createAgent();
    await prisma.behaviorEvent.create({
      data: { agentId: agent.id, userId: 'WORKSTATION\\jdoe', eventType: 'FILE_ACCESS', metadata: {} },
    });

    const res = await request(app)
      .post('/api/ueba/baseline/WORKSTATION%5Cjdoe/recompute?days=14')
      .set('Authorization', authHeader(user));

    expect(res.status).toBe(200);

    const logs = await prisma.auditLog.findMany({ where: { action: 'RECOMPUTE_BEHAVIOR_BASELINE' } });
    expect(logs).toHaveLength(1);
    expect(logs[0].metadata.source).toBe('RECOMPUTED');
    expect(logs[0].metadata.days).toBe(14);
  });

  test('deleting an agent is recorded with the hostname it destroys', async () => {
    const { user } = await createUser({ role: 'ADMIN' });
    const agent = await createAgent({ hostname: 'FINANCE-WS-04' });

    const res = await request(app)
      .delete(`/api/agents/${agent.id}`)
      .set('Authorization', authHeader(user));

    expect(res.status).toBe(204);

    const logs = await prisma.auditLog.findMany({ where: { action: 'DELETE_AGENT' } });
    expect(logs).toHaveLength(1);
    expect(logs[0].metadata.hostname).toBe('FINANCE-WS-04');
  });

  test('deleting a non-existent agent 404s and records nothing', async () => {
    const { user } = await createUser({ role: 'ADMIN' });
    const res = await request(app)
      .delete('/api/agents/00000000-0000-0000-0000-000000000000')
      .set('Authorization', authHeader(user));

    expect(res.status).toBe(404);
    expect(await prisma.auditLog.count({ where: { action: 'DELETE_AGENT' } })).toBe(0);
  });

  test('an incident update still records, alongside the new coverage', async () => {
    const { user } = await createUser({ role: 'ADMIN' });
    const agent = await createAgent();
    const policy = await createPolicy();
    const incident = await prisma.incident.create({
      data: { agentId: agent.id, policyId: policy.id, channel: 'CLIPBOARD', severity: 'HIGH' },
    });

    await request(app)
      .patch(`/api/incidents/${incident.id}`)
      .set('Authorization', authHeader(user))
      .send({ status: 'RESOLVED' });

    const res = await request(app)
      .get(`/api/audit/resource/incident/${incident.id}`)
      .set('Authorization', authHeader(user));

    expect(res.body.logs.length).toBeGreaterThan(0);
  });
});
