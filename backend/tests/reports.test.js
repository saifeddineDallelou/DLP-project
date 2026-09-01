const request = require('supertest');
const app = require('../src/app');
const {
  prisma, resetDb, createUser, authHeader, createAgent, createPolicy,
} = require('./helpers');

afterEach(resetDb);
afterAll(() => prisma.$disconnect());

describe('GET /api/reports/daily', () => {
  test('requires authentication', async () => {
    const res = await request(app).get('/api/reports/daily');
    expect(res.status).toBe(401);
  });

  test('rejects a malformed date', async () => {
    const { user } = await createUser();
    const res = await request(app)
      .get('/api/reports/daily?date=not-a-date')
      .set('Authorization', authHeader(user));
    expect(res.status).toBe(400);
  });

  test('defaults to today and returns an empty timeline when nothing happened', async () => {
    const { user } = await createUser();
    const res = await request(app)
      .get('/api/reports/daily')
      .set('Authorization', authHeader(user));

    expect(res.status).toBe(200);
    expect(res.body.timeline).toEqual([]);
    expect(res.body.summary.totalIncidents).toBe(0);
    expect(res.body.summary.totalAiLeakAttempts).toBe(0);
  });

  test('merges incidents and AI leak attempts for the given day, sorted chronologically', async () => {
    const { user } = await createUser();
    const agent = await createAgent();
    const policy = await createPolicy();
    const today = new Date().toISOString().slice(0, 10);

    await prisma.incident.create({
      data: { agentId: agent.id, policyId: policy.id, channel: 'CLIPBOARD', reviewRequested: true, justification: 'thought it was fine' },
    });
    await prisma.aiLeakAttempt.create({
      data: { agentId: agent.id, policyId: policy.id, platform: 'GROK', method: 'BROWSER', riskScore: 0.9 },
    });

    const res = await request(app)
      .get(`/api/reports/daily?date=${today}`)
      .set('Authorization', authHeader(user));

    expect(res.status).toBe(200);
    expect(res.body.timeline.length).toBe(2);
    expect(res.body.summary.totalIncidents).toBe(1);
    expect(res.body.summary.totalAiLeakAttempts).toBe(1);
    expect(res.body.summary.reviewRequested).toBe(1);
    expect(res.body.summary.needsAdminNote).toBe(1);
    const kinds = res.body.timeline.map(t => t.kind).sort();
    expect(kinds).toEqual(['AI_LEAK_ATTEMPT', 'INCIDENT']);
  });

  test('excludes incidents from other days', async () => {
    const { user } = await createUser();
    const agent = await createAgent();
    const policy = await createPolicy();

    const yesterday = new Date();
    yesterday.setDate(yesterday.getDate() - 1);
    const incident = await prisma.incident.create({
      data: { agentId: agent.id, policyId: policy.id, channel: 'CLIPBOARD' },
    });
    await prisma.incident.update({ where: { id: incident.id }, data: { createdAt: yesterday } });

    const today = new Date().toISOString().slice(0, 10);
    const res = await request(app)
      .get(`/api/reports/daily?date=${today}`)
      .set('Authorization', authHeader(user));

    expect(res.status).toBe(200);
    expect(res.body.timeline).toEqual([]);
  });
});
