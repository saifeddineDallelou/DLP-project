const request = require('supertest');
const app = require('../src/app');
const { prisma, resetDb, createUser, authHeader, createAgent } = require('./helpers');

afterEach(resetDb);
afterAll(() => prisma.$disconnect());

describe('POST /api/ai-policy/attempt', () => {
  test('validates required fields', async () => {
    const res = await request(app).post('/api/ai-policy/attempt').send({});
    expect(res.status).toBe(400);
  });

  test('rejects missing auth', async () => {
    const agent = await createAgent();
    const res = await request(app)
      .post('/api/ai-policy/attempt')
      .send({ agentId: agent.id, platform: 'OPENAI_CHATGPT', method: 'CLIPBOARD', riskScore: 0.9 });
    expect(res.status).toBe(401);
  });

  test('accepts agent-token auth and creates a record', async () => {
    const agent = await createAgent();
    const res = await request(app)
      .post('/api/ai-policy/attempt')
      .set('x-agent-token', agent.token)
      .send({
        agentId: agent.id,
        platform: 'ANTHROPIC_CLAUDE',
        method: 'CLIPBOARD',
        contentSample: 'card: 4111111111111111',
        riskScore: 0.92,
      });

    expect(res.status).toBe(201);
    expect(res.body.platform).toBe('ANTHROPIC_CLAUDE');
    expect(res.body.blocked).toBe(true); // default
  });

  test('rejects wrong agent token', async () => {
    const agent = await createAgent();
    const res = await request(app)
      .post('/api/ai-policy/attempt')
      .set('x-agent-token', 'wrong')
      .send({ agentId: agent.id, platform: 'GROK', method: 'BROWSER', riskScore: 0.5 });
    expect(res.status).toBe(401);
  });
});

describe('GET /api/ai-policy/attempt', () => {
  test('requires auth', async () => {
    const res = await request(app).get('/api/ai-policy/attempt');
    expect(res.status).toBe(401);
  });

  test('returns 404 when no attempts exist', async () => {
    const { user } = await createUser();
    const res = await request(app).get('/api/ai-policy/attempt').set('Authorization', authHeader(user));
    expect(res.status).toBe(404);
  });

  test('returns the most recent attempt for an agent', async () => {
    const { user } = await createUser();
    const agent = await createAgent();
    await prisma.aiLeakAttempt.create({
      data: { agentId: agent.id, platform: 'GOOGLE_GEMINI', method: 'SCREENSHOT', riskScore: 0.4 },
    });

    const res = await request(app)
      .get(`/api/ai-policy/attempt?agentId=${agent.id}`)
      .set('Authorization', authHeader(user));

    expect(res.status).toBe(200);
    expect(res.body.platform).toBe('GOOGLE_GEMINI');
  });
});

describe('GET /api/ai-policy/attempts', () => {
  test('filters by blocked flag and paginates', async () => {
    const { user } = await createUser();
    const agent = await createAgent();
    await prisma.aiLeakAttempt.create({
      data: { agentId: agent.id, platform: 'DEEPSEEK', method: 'BROWSER', riskScore: 0.3, blocked: false },
    });
    await prisma.aiLeakAttempt.create({
      data: { agentId: agent.id, platform: 'DEEPSEEK', method: 'BROWSER', riskScore: 0.9, blocked: true },
    });

    const res = await request(app)
      .get('/api/ai-policy/attempts?blocked=true')
      .set('Authorization', authHeader(user));

    expect(res.status).toBe(200);
    expect(res.body.total).toBe(1);
    expect(res.body.attempts[0].blocked).toBe(true);
  });
});
