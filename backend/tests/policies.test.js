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
