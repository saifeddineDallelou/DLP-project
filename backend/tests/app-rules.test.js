const request = require('supertest');
const app = require('../src/app');
const { prisma, resetDb, createUser, authHeader, createAgent } = require('./helpers');

afterEach(resetDb);
afterAll(() => prisma.$disconnect());

describe('GET /api/app-rules', () => {
  test('accepts agent-token auth', async () => {
    const agent = await createAgent();
    await prisma.appRule.create({ data: { keyword: 'teamviewer', label: 'TeamViewer remote access' } });

    const res = await request(app).get('/api/app-rules').set('x-agent-token', agent.token);

    expect(res.status).toBe(200);
    expect(res.body).toHaveLength(1);
    expect(res.body[0].keyword).toBe('teamviewer');
  });

  test('accepts JWT Bearer auth', async () => {
    const { user } = await createUser();
    const res = await request(app).get('/api/app-rules').set('Authorization', authHeader(user));
    expect(res.status).toBe(200);
  });

  test('rejects missing auth', async () => {
    const res = await request(app).get('/api/app-rules');
    expect(res.status).toBe(401);
  });

  test('filters by enabled', async () => {
    const { user } = await createUser();
    await prisma.appRule.create({ data: { keyword: 'teamviewer', label: 'TeamViewer', enabled: true } });
    await prisma.appRule.create({ data: { keyword: 'winrar', label: 'WinRAR', enabled: false } });

    const res = await request(app)
      .get('/api/app-rules?enabled=true')
      .set('Authorization', authHeader(user));

    expect(res.status).toBe(200);
    expect(res.body).toHaveLength(1);
    expect(res.body[0].keyword).toBe('teamviewer');
  });
});

describe('POST /api/app-rules', () => {
  test('requires ADMIN/ANALYST role', async () => {
    const { user } = await createUser({ role: 'VIEWER' });
    const res = await request(app)
      .post('/api/app-rules')
      .set('Authorization', authHeader(user))
      .send({ keyword: 'teamviewer', label: 'TeamViewer' });
    expect(res.status).toBe(403);
  });

  test('creates a rule, lowercasing the keyword', async () => {
    const { user } = await createUser({ role: 'ADMIN' });
    const res = await request(app)
      .post('/api/app-rules')
      .set('Authorization', authHeader(user))
      .send({ keyword: 'TeamViewer', label: 'TeamViewer remote access' });

    expect(res.status).toBe(201);
    expect(res.body.keyword).toBe('teamviewer');
    expect(res.body.enabled).toBe(true);
  });

  test('rejects a duplicate keyword', async () => {
    const { user } = await createUser({ role: 'ADMIN' });
    await prisma.appRule.create({ data: { keyword: 'teamviewer', label: 'TeamViewer' } });

    const res = await request(app)
      .post('/api/app-rules')
      .set('Authorization', authHeader(user))
      .send({ keyword: 'teamviewer', label: 'Duplicate' });

    expect(res.status).toBe(409);
  });

  test('validates required fields', async () => {
    const { user } = await createUser({ role: 'ADMIN' });
    const res = await request(app)
      .post('/api/app-rules')
      .set('Authorization', authHeader(user))
      .send({});
    expect(res.status).toBe(400);
  });
});

describe('PUT /api/app-rules/:id', () => {
  test('updates enabled flag', async () => {
    const { user } = await createUser({ role: 'ADMIN' });
    const rule = await prisma.appRule.create({ data: { keyword: 'teamviewer', label: 'TeamViewer' } });

    const res = await request(app)
      .put(`/api/app-rules/${rule.id}`)
      .set('Authorization', authHeader(user))
      .send({ enabled: false });

    expect(res.status).toBe(200);
    expect(res.body.enabled).toBe(false);
  });

  test('404s for a nonexistent rule', async () => {
    const { user } = await createUser({ role: 'ADMIN' });
    const res = await request(app)
      .put('/api/app-rules/00000000-0000-0000-0000-000000000000')
      .set('Authorization', authHeader(user))
      .send({ enabled: false });
    expect(res.status).toBe(404);
  });
});

describe('DELETE /api/app-rules/:id', () => {
  test('requires ADMIN role specifically', async () => {
    const { user } = await createUser({ role: 'ANALYST' });
    const rule = await prisma.appRule.create({ data: { keyword: 'teamviewer', label: 'TeamViewer' } });

    const res = await request(app)
      .delete(`/api/app-rules/${rule.id}`)
      .set('Authorization', authHeader(user));

    expect(res.status).toBe(403);
  });

  test('deletes a rule', async () => {
    const { user } = await createUser({ role: 'ADMIN' });
    const rule = await prisma.appRule.create({ data: { keyword: 'teamviewer', label: 'TeamViewer' } });

    const res = await request(app)
      .delete(`/api/app-rules/${rule.id}`)
      .set('Authorization', authHeader(user));

    expect(res.status).toBe(204);
    expect(await prisma.appRule.findUnique({ where: { id: rule.id } })).toBeNull();
  });
});
