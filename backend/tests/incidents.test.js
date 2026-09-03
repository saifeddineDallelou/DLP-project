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

describe('PATCH /api/incidents/:id/request-review', () => {
  test('requires x-agent-token', async () => {
    const agent = await createAgent();
    const policy = await createPolicy();
    const incident = await prisma.incident.create({
      data: { agentId: agent.id, policyId: policy.id, channel: 'CLIPBOARD' },
    });
    const res = await request(app)
      .patch(`/api/incidents/${incident.id}/request-review`)
      .send({ note: 'Needed for the client demo' });
    expect(res.status).toBe(401);
  });

  test('rejects a token belonging to a different agent', async () => {
    const owner = await createAgent();
    const other = await createAgent();
    const policy = await createPolicy();
    const incident = await prisma.incident.create({
      data: { agentId: owner.id, policyId: policy.id, channel: 'CLIPBOARD' },
    });
    const res = await request(app)
      .patch(`/api/incidents/${incident.id}/request-review`)
      .set('x-agent-token', other.token)
      .send({ note: 'Needed for the client demo' });
    expect(res.status).toBe(401);
  });

  test('the note is optional -- an empty request still flags it for review', async () => {
    const agent = await createAgent();
    const policy = await createPolicy();
    const incident = await prisma.incident.create({
      data: { agentId: agent.id, policyId: policy.id, channel: 'CLIPBOARD' },
    });
    const res = await request(app)
      .patch(`/api/incidents/${incident.id}/request-review`)
      .set('x-agent-token', agent.token)
      .send({});

    expect(res.status).toBe(200);
    expect(res.body.reviewRequested).toBe(true);
    expect(res.body.justification).toBeNull();
  });

  test('marks the incident reviewRequested with the worker note, but does not resolve it', async () => {
    const agent = await createAgent();
    const policy = await createPolicy();
    const incident = await prisma.incident.create({
      data: { agentId: agent.id, policyId: policy.id, channel: 'CLIPBOARD' },
    });
    const res = await request(app)
      .patch(`/api/incidents/${incident.id}/request-review`)
      .set('x-agent-token', agent.token)
      .send({ note: 'This looked like a false positive to me' });

    expect(res.status).toBe(200);
    expect(res.body.reviewRequested).toBe(true);
    expect(res.body.justification).toBe('This looked like a false positive to me');
    expect(res.body.status).toBe('OPEN');
  });

  test('404s for a nonexistent incident', async () => {
    const agent = await createAgent();
    const res = await request(app)
      .patch('/api/incidents/00000000-0000-0000-0000-000000000000/request-review')
      .set('x-agent-token', agent.token)
      .send({ note: 'x' });
    expect(res.status).toBe(404);
  });
});

describe('PATCH /api/incidents/:id (adminNote)', () => {
  test('an admin can record their explanation after reviewing', async () => {
    const { user } = await createUser({ role: 'ADMIN' });
    const agent = await createAgent();
    const policy = await createPolicy();
    const incident = await prisma.incident.create({
      data: { agentId: agent.id, policyId: policy.id, channel: 'CLIPBOARD', reviewRequested: true },
    });

    const res = await request(app)
      .patch(`/api/incidents/${incident.id}`)
      .set('Authorization', authHeader(user))
      .send({ adminNote: 'Confirmed with the employee -- approved use, closing.', status: 'RESOLVED' });

    expect(res.status).toBe(200);
    expect(res.body.adminNote).toBe('Confirmed with the employee -- approved use, closing.');
    expect(res.body.status).toBe('RESOLVED');
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

describe('a permitted match is auditable, not actionable', () => {
  // ALLOW used to leave no trace at all, which made a sanctioned exception
  // indistinguishable from a hole. It is recorded now -- but it must not sit
  // in the triage queue as OPEN, because there is nothing for an analyst to
  // do about it.
  test('an ALLOW incident lands as ALLOWED, not OPEN', async () => {
    const agent = await createAgent();
    const policy = await prisma.policy.create({
      data: { name: 'Permitted', conditions: {}, action: 'ALLOW', severity: 'LOW' },
    });

    const res = await request(app).post('/api/incidents')
      .set('x-agent-token', agent.token)
      .send({
        agentId: agent.id, policyId: policy.id, severity: 'LOW',
        channel: 'FILE', riskScore: 0.9, actionTaken: 'ALLOW',
      });

    expect(res.status).toBe(201);
    expect(res.body.actionTaken).toBe('ALLOW');
    expect(res.body.status).toBe('ALLOWED');
  });

  test('every other action still opens for triage', async () => {
    const agent = await createAgent();
    const policy = await prisma.policy.create({
      data: { name: 'Blocked', conditions: {}, action: 'BLOCK', severity: 'HIGH' },
    });

    for (const action of ['ALERT', 'BLOCK', 'QUARANTINE']) {
      const res = await request(app).post('/api/incidents')
        .set('x-agent-token', agent.token)
        .send({
          agentId: agent.id, policyId: policy.id, severity: 'HIGH',
          channel: 'FILE', riskScore: 0.9, actionTaken: action,
        });
      expect(res.body.status).toBe('OPEN');
      expect(res.body.actionTaken).toBe(action);
    }
  });

  test('an incident with no recorded action is unaffected', async () => {
    // Older agents do not send the field; they must keep working.
    const agent = await createAgent();
    const policy = await prisma.policy.create({
      data: { name: 'Legacy', conditions: {}, action: 'BLOCK', severity: 'HIGH' },
    });

    const res = await request(app).post('/api/incidents')
      .set('x-agent-token', agent.token)
      .send({ agentId: agent.id, policyId: policy.id, severity: 'HIGH', channel: 'FILE' });

    expect(res.status).toBe(201);
    expect(res.body.actionTaken).toBeNull();
    expect(res.body.status).toBe('OPEN');
  });
});
