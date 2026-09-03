const request = require('supertest');
const app = require('../src/app');
const { prisma, resetDb, createUser, authHeader, createPolicy, createAgent } = require('./helpers');

afterEach(resetDb);
afterAll(() => prisma.$disconnect());

describe('policies routes', () => {
  test('GET / requires auth', async () => {
    const res = await request(app).get('/api/policies');
    expect(res.status).toBe(401);
  });

  test('GET / accepts agent-token auth (agent reads policies at startup)', async () => {
    const agent = await createAgent();
    await createPolicy({ name: 'PCI-DSS Policy' });

    const res = await request(app)
      .get('/api/policies')
      .set('x-agent-token', agent.token);

    expect(res.status).toBe(200);
    expect(res.body).toHaveLength(1);
  });

  test('GET / rejects invalid agent-token', async () => {
    const res = await request(app)
      .get('/api/policies')
      .set('x-agent-token', 'not-a-real-token');
    expect(res.status).toBe(401);
  });

  test('GET / lists policies, filterable by enabled', async () => {
    const { user } = await createUser();
    await createPolicy({ name: 'Enabled one' });
    const disabled = await createPolicy({ name: 'Disabled one' });
    await prisma.policy.update({ where: { id: disabled.id }, data: { enabled: false } });

    const res = await request(app)
      .get('/api/policies?enabled=false')
      .set('Authorization', authHeader(user));

    expect(res.status).toBe(200);
    expect(res.body).toHaveLength(1);
    expect(res.body[0].name).toBe('Disabled one');
  });

  test('GET /:id returns 404 for unknown id', async () => {
    const { user } = await createUser();
    const res = await request(app)
      .get('/api/policies/00000000-0000-0000-0000-000000000000')
      .set('Authorization', authHeader(user));
    expect(res.status).toBe(404);
  });

  test('POST / requires ADMIN or ANALYST role', async () => {
    const { user } = await createUser({ role: 'VIEWER' });
    const res = await request(app)
      .post('/api/policies')
      .set('Authorization', authHeader(user))
      .send({ name: 'x', conditions: {} });
    expect(res.status).toBe(403);
  });

  test('POST / validates required fields', async () => {
    const { user } = await createUser({ role: 'ANALYST' });
    const res = await request(app)
      .post('/api/policies')
      .set('Authorization', authHeader(user))
      .send({ name: 'missing conditions' });
    expect(res.status).toBe(400);
  });

  test('POST / creates a policy and an audit log entry', async () => {
    const { user } = await createUser({ role: 'ANALYST' });
    const res = await request(app)
      .post('/api/policies')
      .set('Authorization', authHeader(user))
      .send({ name: 'New Policy', conditions: { patterns: ['EMAIL'] } });

    expect(res.status).toBe(201);
    expect(res.body.name).toBe('New Policy');

    const logs = await prisma.auditLog.findMany({ where: { action: 'CREATE_POLICY' } });
    expect(logs).toHaveLength(1);
    expect(logs[0].userId).toBe(user.id);
  });

  test('PUT /:id updates fields and bumps version', async () => {
    const { user } = await createUser({ role: 'ADMIN' });
    const policy = await createPolicy();

    const res = await request(app)
      .put(`/api/policies/${policy.id}`)
      .set('Authorization', authHeader(user))
      .send({ severity: 'CRITICAL' });

    expect(res.status).toBe(200);
    expect(res.body.severity).toBe('CRITICAL');
    expect(res.body.version).toBe(2);
  });

  test('PUT /:id returns 404 for unknown id', async () => {
    const { user } = await createUser({ role: 'ADMIN' });
    const res = await request(app)
      .put('/api/policies/00000000-0000-0000-0000-000000000000')
      .set('Authorization', authHeader(user))
      .send({ severity: 'LOW' });
    expect(res.status).toBe(404);
  });

  test('DELETE /:id requires ADMIN role', async () => {
    const { user } = await createUser({ role: 'ANALYST' });
    const policy = await createPolicy();
    const res = await request(app)
      .delete(`/api/policies/${policy.id}`)
      .set('Authorization', authHeader(user));
    expect(res.status).toBe(403);
  });

  test('DELETE /:id removes the policy as ADMIN', async () => {
    const { user } = await createUser({ role: 'ADMIN' });
    const policy = await createPolicy();
    const res = await request(app)
      .delete(`/api/policies/${policy.id}`)
      .set('Authorization', authHeader(user));
    expect(res.status).toBe(204);

    const found = await prisma.policy.findUnique({ where: { id: policy.id } });
    expect(found).toBeNull();
  });
});

describe('per-channel policy actions', () => {
  // The right response depends on where data is moving. A paste can be
  // stopped in flight; a file already sitting in a folder cannot, so BLOCK
  // there only ever wrote an incident while claiming to have blocked
  // something. The pairing is validated here rather than discovered later by
  // an operator wondering why nothing happened.
  async function admin() {
    const { user } = await createUser({ role: 'ADMIN' });
    return user;
  }
  const BASE = {
    name: 'PII Detection',
    conditions: { complianceRule: 'GDPR', threshold: 1 },
    action: 'BLOCK',
    severity: 'HIGH',
  };

  test('stores a valid per-channel override', async () => {
    const user = await admin();
    const res = await request(app).post('/api/policies')
      .set('Authorization', authHeader(user))
      .send({ ...BASE, channelActions: { FILE: 'QUARANTINE', CLIPBOARD: 'BLOCK' } });

    expect(res.status).toBe(201);
    expect(res.body.channelActions).toEqual({ FILE: 'QUARANTINE', CLIPBOARD: 'BLOCK' });
  });

  test('a policy without overrides still works', async () => {
    const user = await admin();
    const res = await request(app).post('/api/policies')
      .set('Authorization', authHeader(user)).send(BASE);
    expect(res.status).toBe(201);
    expect(res.body.channelActions).toBeNull();
  });

  test('rejects BLOCK on a file at rest, and says why', async () => {
    // This is the exact configuration that silently did nothing.
    const user = await admin();
    const res = await request(app).post('/api/policies')
      .set('Authorization', authHeader(user))
      .send({ ...BASE, channelActions: { FILE: 'BLOCK' } });

    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/nothing in flight to intercept/i);
    expect(res.body.error).toMatch(/QUARANTINE/);
  });

  test('rejects QUARANTINE on an in-flight channel', async () => {
    // There is no file to move when someone pastes.
    const user = await admin();
    const res = await request(app).post('/api/policies')
      .set('Authorization', authHeader(user))
      .send({ ...BASE, channelActions: { CLIPBOARD: 'QUARANTINE' } });

    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/only meaningful for data at rest/i);
  });

  test('rejects an unknown channel', async () => {
    const user = await admin();
    const res = await request(app).post('/api/policies')
      .set('Authorization', authHeader(user))
      .send({ ...BASE, channelActions: { CARRIER_PIGEON: 'BLOCK' } });

    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/Unknown channel/i);
  });

  test('rejects an action that is not one of the four', async () => {
    // The column is Json, so Postgres would store anything -- and an endpoint
    // agent would then receive it as the action to enforce.
    const user = await admin();
    const res = await request(app).post('/api/policies')
      .set('Authorization', authHeader(user))
      .send({ ...BASE, channelActions: { FILE: 'DELETE_EVERYTHING' } });

    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/Invalid action/i);
  });

  test('rejects a non-object', async () => {
    const user = await admin();
    const res = await request(app).post('/api/policies')
      .set('Authorization', authHeader(user))
      .send({ ...BASE, channelActions: ['FILE', 'QUARANTINE'] });

    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/must be an object/i);
  });

  test('an update can add overrides to an existing policy', async () => {
    const user = await admin();
    const created = await request(app).post('/api/policies')
      .set('Authorization', authHeader(user)).send(BASE);

    const res = await request(app).put(`/api/policies/${created.body.id}`)
      .set('Authorization', authHeader(user))
      .send({ channelActions: { FILE: 'QUARANTINE' } });

    expect(res.status).toBe(200);
    expect(res.body.channelActions).toEqual({ FILE: 'QUARANTINE' });
  });

  test('an invalid update does not change the stored policy', async () => {
    const user = await admin();
    const created = await request(app).post('/api/policies')
      .set('Authorization', authHeader(user))
      .send({ ...BASE, channelActions: { FILE: 'QUARANTINE' } });

    await request(app).put(`/api/policies/${created.body.id}`)
      .set('Authorization', authHeader(user))
      .send({ channelActions: { FILE: 'BLOCK' } });

    const after = await prisma.policy.findUnique({ where: { id: created.body.id } });
    expect(after.channelActions).toEqual({ FILE: 'QUARANTINE' });
  });
});

describe('risk ladders on a policy', () => {
  // risk, severity and action were three fields nothing reconciled -- which
  // is how an incident could read "risk 0.93, severity CRITICAL, action
  // ALLOW". A ladder makes confidence choose the tier and the tier carry both
  // of the others.
  const BASE = {
    name: 'PII Detection',
    conditions: { complianceRule: 'GDPR', threshold: 1 },
    action: 'ALERT',
    severity: 'MEDIUM',
  };
  async function admin() {
    const { user } = await createUser({ role: 'ADMIN' });
    return user;
  }

  test('stores a well-formed ladder', async () => {
    const user = await admin();
    const res = await request(app).post('/api/policies')
      .set('Authorization', authHeader(user))
      .send({ ...BASE, tiers: [
        { minRisk: 0.9, action: 'QUARANTINE', severity: 'CRITICAL' },
        { minRisk: 0.7, action: 'ALERT', severity: 'HIGH' },
      ] });

    expect(res.status).toBe(201);
    expect(res.body.tiers).toHaveLength(2);
  });

  test('a policy without a ladder still works', async () => {
    const user = await admin();
    const res = await request(app).post('/api/policies')
      .set('Authorization', authHeader(user)).send(BASE);
    expect(res.status).toBe(201);
    expect(res.body.tiers).toBeNull();
  });

  test('rejects a ladder that gets softer as confidence rises', async () => {
    // The silent version of this gives the strongest evidence the weakest
    // response, and nothing about the stored policy would look wrong.
    const user = await admin();
    const res = await request(app).post('/api/policies')
      .set('Authorization', authHeader(user))
      .send({ ...BASE, tiers: [
        { minRisk: 0.5, action: 'QUARANTINE' },
        { minRisk: 0.9, action: 'ALERT' },
      ] });

    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/more weakly|softer response/i);
  });

  test('rejects two tiers at the same threshold', async () => {
    // Which one applies would depend on array order.
    const user = await admin();
    const res = await request(app).post('/api/policies')
      .set('Authorization', authHeader(user))
      .send({ ...BASE, tiers: [
        { minRisk: 0.8, action: 'ALERT' },
        { minRisk: 0.8, action: 'QUARANTINE' },
      ] });

    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/distinct/i);
  });

  test('rejects a threshold outside 0..1', async () => {
    const user = await admin();
    for (const minRisk of [-0.1, 1.5, 'high', null]) {
      const res = await request(app).post('/api/policies')
        .set('Authorization', authHeader(user))
        .send({ ...BASE, tiers: [{ minRisk, action: 'ALERT' }] });
      expect(res.status).toBe(400);
      expect(res.body.error).toMatch(/between 0 and 1/i);
    }
  });

  test('rejects an action outside the enum', async () => {
    const user = await admin();
    const res = await request(app).post('/api/policies')
      .set('Authorization', authHeader(user))
      .send({ ...BASE, tiers: [{ minRisk: 0.9, action: 'rm -rf' }] });

    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/Invalid action/i);
  });

  test('rejects a non-array', async () => {
    const user = await admin();
    const res = await request(app).post('/api/policies')
      .set('Authorization', authHeader(user))
      .send({ ...BASE, tiers: { minRisk: 0.9, action: 'ALERT' } });

    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/must be an array/i);
  });

  test('an equal response at a higher threshold is allowed', async () => {
    // BLOCK then QUARANTINE is not an escalation problem: they are the same
    // intent realised on different channels.
    const user = await admin();
    const res = await request(app).post('/api/policies')
      .set('Authorization', authHeader(user))
      .send({ ...BASE, tiers: [
        { minRisk: 0.7, action: 'BLOCK' },
        { minRisk: 0.9, action: 'QUARANTINE' },
      ] });

    expect(res.status).toBe(201);
  });
});
