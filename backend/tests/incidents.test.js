const request = require('supertest');
const app = require('../src/app');
const {
  prisma, resetDb, createUser, authHeader, createAgent, createPolicy,
} = require('./helpers');

afterEach(resetDb);
afterAll(() => prisma.$disconnect());

describe('POST /api/incidents', () => {
  test('requires authentication', async () => {
    const res = await request(app).post('/api/incidents').send({});
    expect(res.status).toBe(401);
  });

  test('accepts agent-token auth and creates an incident', async () => {
    const agent = await createAgent();
    const policy = await createPolicy();

    const res = await request(app)
      .post('/api/incidents')
      .set('x-agent-token', agent.token)
      .send({ policyId: policy.id, channel: 'CLIPBOARD', evidence: 'leaked text' });

    expect(res.status).toBe(201);
    expect(res.body.agentId).toBe(agent.id);
    expect(res.body.status).toBe('OPEN');
    expect(res.body.evidenceType).toBe('text');
  });

  test('rejects invalid agent token', async () => {
    const policy = await createPolicy();
    const res = await request(app)
      .post('/api/incidents')
      .set('x-agent-token', 'nope')
      .send({ policyId: policy.id, channel: 'CLIPBOARD' });
    expect(res.status).toBe(401);
  });

  test('accepts JWT auth and requires explicit agentId', async () => {
    const { user } = await createUser();
    const agent = await createAgent();
    const policy = await createPolicy();

    const res = await request(app)
      .post('/api/incidents')
      .set('Authorization', authHeader(user))
      .send({ agentId: agent.id, policyId: policy.id, channel: 'USB' });

    expect(res.status).toBe(201);
    expect(res.body.agentId).toBe(agent.id);
  });

  test('rejects invalid policyId with 400', async () => {
    const agent = await createAgent();
    const res = await request(app)
      .post('/api/incidents')
      .set('x-agent-token', agent.token)
      .send({ policyId: 'does-not-exist', channel: 'FILE' });
    expect(res.status).toBe(400);
  });

  test('validates required fields', async () => {
    const agent = await createAgent();
    const res = await request(app)
      .post('/api/incidents')
      .set('x-agent-token', agent.token)
      .send({});
    expect(res.status).toBe(400);
  });
});

describe('GET /api/incidents', () => {
  test('requires auth', async () => {
    const res = await request(app).get('/api/incidents');
    expect(res.status).toBe(401);
  });

  test('paginates and filters by status/severity/agentId', async () => {
    const { user } = await createUser();
    const agent = await createAgent();
    const policy = await createPolicy();

    for (let i = 0; i < 3; i++) {
      await prisma.incident.create({
        data: {
          agentId: agent.id,
          policyId: policy.id,
          severity: i === 0 ? 'CRITICAL' : 'LOW',
          channel: 'FILE',
        },
      });
    }

    const res = await request(app)
      .get('/api/incidents?severity=CRITICAL')
      .set('Authorization', authHeader(user));

    expect(res.status).toBe(200);
    expect(res.body.total).toBe(1);
    expect(res.body.incidents).toHaveLength(1);
    expect(res.body.incidents[0].severity).toBe('CRITICAL');
  });
});

describe('GET /api/incidents/:id', () => {
  test('returns 404 for unknown id', async () => {
    const { user } = await createUser();
    const res = await request(app)
      .get('/api/incidents/00000000-0000-0000-0000-000000000000')
      .set('Authorization', authHeader(user));
    expect(res.status).toBe(404);
  });

  test('returns the full incident with relations', async () => {
    const { user } = await createUser();
    const agent = await createAgent();
    const policy = await createPolicy();
    const incident = await prisma.incident.create({
      data: { agentId: agent.id, policyId: policy.id, channel: 'PRINT' },
    });

    const res = await request(app)
      .get(`/api/incidents/${incident.id}`)
      .set('Authorization', authHeader(user));

    expect(res.status).toBe(200);
    expect(res.body.agent.hostname).toBe(agent.hostname);
    expect(res.body.policy.name).toBe(policy.name);
  });
});

describe('PATCH /api/incidents/:id', () => {
  test('requires ADMIN or ANALYST role', async () => {
    const { user } = await createUser({ role: 'VIEWER' });
    const agent = await createAgent();
    const policy = await createPolicy();
    const incident = await prisma.incident.create({
      data: { agentId: agent.id, policyId: policy.id, channel: 'NETWORK' },
    });

    const res = await request(app)
      .patch(`/api/incidents/${incident.id}`)
      .set('Authorization', authHeader(user))
      .send({ status: 'RESOLVED' });
    expect(res.status).toBe(403);
  });

  test('resolving sets resolvedAt and writes an audit log', async () => {
    const { user } = await createUser({ role: 'ANALYST' });
    const agent = await createAgent();
    const policy = await createPolicy();
    const incident = await prisma.incident.create({
      data: { agentId: agent.id, policyId: policy.id, channel: 'SCREENSHOT' },
    });

    const res = await request(app)
      .patch(`/api/incidents/${incident.id}`)
      .set('Authorization', authHeader(user))
      .send({ status: 'RESOLVED' });

    expect(res.status).toBe(200);
    expect(res.body.status).toBe('RESOLVED');
    expect(res.body.resolvedAt).toBeDefined();

    const logs = await prisma.auditLog.findMany({ where: { action: 'UPDATE_INCIDENT' } });
    expect(logs).toHaveLength(1);
  });
});
