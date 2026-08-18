const request = require('supertest');
const app = require('../src/app');
const { prisma, resetDb, createUser, authHeader, createAgent } = require('./helpers');

afterEach(resetDb);
afterAll(() => prisma.$disconnect());

describe('agents routes', () => {
  test('GET / requires auth', async () => {
    const res = await request(app).get('/api/agents');
    expect(res.status).toBe(401);
  });

  test('GET / lists agents without exposing tokens', async () => {
    const { user } = await createUser();
    await createAgent({ hostname: 'ws-1' });
    const res = await request(app).get('/api/agents').set('Authorization', authHeader(user));
    expect(res.status).toBe(200);
    expect(res.body).toHaveLength(1);
    expect(res.body[0].token).toBeUndefined();
  });

  test('POST /enroll requires no auth and returns a token', async () => {
    const res = await request(app)
      .post('/api/agents/enroll')
      .send({ hostname: 'new-workstation', os: 'Windows 11' });

    expect(res.status).toBe(201);
    expect(res.body.token).toBeDefined();
    expect(res.body.hostname).toBe('new-workstation');
  });

  test('POST /enroll validates required fields', async () => {
    const res = await request(app).post('/api/agents/enroll').send({ hostname: 'x' });
    expect(res.status).toBe(400);
  });

  test('POST /enroll rejects duplicate hostname', async () => {
    await createAgent({ hostname: 'dup-host' });
    const res = await request(app)
      .post('/api/agents/enroll')
      .send({ hostname: 'dup-host', os: 'Windows 11' });
    expect(res.status).toBe(409);
  });

  test('PATCH /:id/heartbeat rejects wrong agent token', async () => {
    const agent = await createAgent();
    const res = await request(app)
      .patch(`/api/agents/${agent.id}/heartbeat`)
      .set('x-agent-token', 'wrong-token');
    expect(res.status).toBe(401);
  });

  test('PATCH /:id/heartbeat updates lastSeen and status with correct token', async () => {
    const agent = await createAgent({ status: 'INACTIVE' });
    const res = await request(app)
      .patch(`/api/agents/${agent.id}/heartbeat`)
      .set('x-agent-token', agent.token);

    expect(res.status).toBe(200);
    expect(res.body.status).toBe('ACTIVE');
    expect(res.body.lastSeen).toBeDefined();
  });

  test('DELETE /:id requires ADMIN role', async () => {
    const { user } = await createUser({ role: 'ANALYST' });
    const agent = await createAgent();
    const res = await request(app)
      .delete(`/api/agents/${agent.id}`)
      .set('Authorization', authHeader(user));
    expect(res.status).toBe(403);
  });

  test('DELETE /:id removes the agent as ADMIN', async () => {
    const { user } = await createUser({ role: 'ADMIN' });
    const agent = await createAgent();
    const res = await request(app)
      .delete(`/api/agents/${agent.id}`)
      .set('Authorization', authHeader(user));
    expect(res.status).toBe(204);

    const found = await prisma.agent.findUnique({ where: { id: agent.id } });
    expect(found).toBeNull();
  });

  test('DELETE /:id returns 404 for unknown id', async () => {
    const { user } = await createUser({ role: 'ADMIN' });
    const res = await request(app)
      .delete('/api/agents/00000000-0000-0000-0000-000000000000')
      .set('Authorization', authHeader(user));
    expect(res.status).toBe(404);
  });
});
