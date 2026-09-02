const request = require('supertest');
const app = require('../src/app');
const { prisma, resetDb, createUser, authHeader, createAgent, createPolicy } = require('./helpers');

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

  test('links the attempt to the given policyId', async () => {
    const agent = await createAgent();
    const policy = await createPolicy({ name: 'PCI Policy' });
    const res = await request(app)
      .post('/api/ai-policy/attempt')
      .set('x-agent-token', agent.token)
      .send({
        agentId: agent.id,
        policyId: policy.id,
        platform: 'OPENAI_CHATGPT',
        method: 'CLIPBOARD',
        riskScore: 0.8,
      });

    expect(res.status).toBe(201);
    expect(res.body.policyId).toBe(policy.id);
  });

  test('records the attempt without a policy link when policyId is unrecognised', async () => {
    const agent = await createAgent();
    const res = await request(app)
      .post('/api/ai-policy/attempt')
      .set('x-agent-token', agent.token)
      .send({
        agentId: agent.id,
        policyId: 'does-not-exist',
        platform: 'OPENAI_CHATGPT',
        method: 'CLIPBOARD',
        riskScore: 0.8,
      });

    expect(res.status).toBe(201);
    expect(res.body.policyId).toBeNull();
  });

  test('defaults policyId to null when omitted', async () => {
    const agent = await createAgent();
    const res = await request(app)
      .post('/api/ai-policy/attempt')
      .set('x-agent-token', agent.token)
      .send({ agentId: agent.id, platform: 'GROK', method: 'BROWSER', riskScore: 0.5 });

    expect(res.status).toBe(201);
    expect(res.body.policyId).toBeNull();
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

  test('includes the linked policy in each attempt', async () => {
    const { user } = await createUser();
    const agent = await createAgent();
    const policy = await createPolicy({ name: 'HIPAA Policy' });
    await prisma.aiLeakAttempt.create({
      data: { agentId: agent.id, policyId: policy.id, platform: 'GROK', method: 'BROWSER', riskScore: 0.6 },
    });

    const res = await request(app)
      .get('/api/ai-policy/attempts')
      .set('Authorization', authHeader(user));

    expect(res.status).toBe(200);
    expect(res.body.attempts[0].policy.name).toBe('HIPAA Policy');
  });
});

describe('PATCH /api/ai-policy/attempt/:id/request-review', () => {
  test('requires x-agent-token', async () => {
    const agent = await createAgent();
    const attempt = await prisma.aiLeakAttempt.create({
      data: { agentId: agent.id, platform: 'GROK', method: 'BROWSER', riskScore: 0.6 },
    });
    const res = await request(app)
      .patch(`/api/ai-policy/attempt/${attempt.id}/request-review`)
      .send({ note: 'Pre-approved sample for support ticket' });
    expect(res.status).toBe(401);
  });

  test('rejects a token belonging to a different agent', async () => {
    const owner = await createAgent();
    const other = await createAgent();
    const attempt = await prisma.aiLeakAttempt.create({
      data: { agentId: owner.id, platform: 'GROK', method: 'BROWSER', riskScore: 0.6 },
    });
    const res = await request(app)
      .patch(`/api/ai-policy/attempt/${attempt.id}/request-review`)
      .set('x-agent-token', other.token)
      .send({ note: 'x' });
    expect(res.status).toBe(401);
  });

  test('the note is optional -- an empty request still flags it for review', async () => {
    const agent = await createAgent();
    const attempt = await prisma.aiLeakAttempt.create({
      data: { agentId: agent.id, platform: 'GROK', method: 'BROWSER', riskScore: 0.6 },
    });
    const res = await request(app)
      .patch(`/api/ai-policy/attempt/${attempt.id}/request-review`)
      .set('x-agent-token', agent.token)
      .send({});

    expect(res.status).toBe(200);
    expect(res.body.reviewRequested).toBe(true);
    expect(res.body.justification).toBeNull();
  });

  test('marks the attempt reviewRequested with the worker note', async () => {
    const agent = await createAgent();
    const attempt = await prisma.aiLeakAttempt.create({
      data: { agentId: agent.id, platform: 'GROK', method: 'BROWSER', riskScore: 0.6 },
    });
    const res = await request(app)
      .patch(`/api/ai-policy/attempt/${attempt.id}/request-review`)
      .set('x-agent-token', agent.token)
      .send({ note: 'Approved by manager over Slack' });

    expect(res.status).toBe(200);
    expect(res.body.reviewRequested).toBe(true);
    expect(res.body.justification).toBe('Approved by manager over Slack');
  });

  test('404s for a nonexistent attempt', async () => {
    const agent = await createAgent();
    const res = await request(app)
      .patch('/api/ai-policy/attempt/00000000-0000-0000-0000-000000000000/request-review')
      .set('x-agent-token', agent.token)
      .send({ note: 'x' });
    expect(res.status).toBe(404);
  });
});

describe('PATCH /api/ai-policy/attempt/:id (adminNote)', () => {
  test('an admin can record their explanation after reviewing', async () => {
    const { user } = await createUser({ role: 'ADMIN' });
    const agent = await createAgent();
    const attempt = await prisma.aiLeakAttempt.create({
      data: { agentId: agent.id, platform: 'GROK', method: 'BROWSER', riskScore: 0.6, reviewRequested: true },
    });

    const res = await request(app)
      .patch(`/api/ai-policy/attempt/${attempt.id}`)
      .set('Authorization', authHeader(user))
      .send({ adminNote: 'Checked with the worker -- legitimate use, no action needed.' });

    expect(res.status).toBe(200);
    expect(res.body.adminNote).toBe('Checked with the worker -- legitimate use, no action needed.');
  });

  test('requires authentication', async () => {
    const agent = await createAgent();
    const attempt = await prisma.aiLeakAttempt.create({
      data: { agentId: agent.id, platform: 'GROK', method: 'BROWSER', riskScore: 0.6 },
    });
    const res = await request(app)
      .patch(`/api/ai-policy/attempt/${attempt.id}`)
      .send({ adminNote: 'x' });
    expect(res.status).toBe(401);
  });
});

describe('PATCH /api/ai-policy/attempt/:id/repeat', () => {
  test('requires x-agent-token', async () => {
    const agent = await createAgent();
    const attempt = await prisma.aiLeakAttempt.create({
      data: { agentId: agent.id, platform: 'GROK', method: 'BROWSER', riskScore: 0.6 },
    });
    const res = await request(app).patch(`/api/ai-policy/attempt/${attempt.id}/repeat`);
    expect(res.status).toBe(401);
  });

  test('rejects a token belonging to a different agent', async () => {
    const owner = await createAgent();
    const other = await createAgent();
    const attempt = await prisma.aiLeakAttempt.create({
      data: { agentId: owner.id, platform: 'GROK', method: 'BROWSER', riskScore: 0.6 },
    });
    const res = await request(app)
      .patch(`/api/ai-policy/attempt/${attempt.id}/repeat`)
      .set('x-agent-token', other.token);
    expect(res.status).toBe(401);
  });

  test('404s for an attempt that does not exist', async () => {
    const agent = await createAgent();
    const res = await request(app)
      .patch('/api/ai-policy/attempt/00000000-0000-0000-0000-000000000000/repeat')
      .set('x-agent-token', agent.token);
    expect(res.status).toBe(404);
  });

  test('a new attempt starts at 1', async () => {
    const agent = await createAgent();
    const attempt = await prisma.aiLeakAttempt.create({
      data: { agentId: agent.id, platform: 'GROK', method: 'BROWSER', riskScore: 0.6 },
    });
    expect(attempt.attempts).toBe(1);
    expect(attempt.lastAttemptAt).toBeNull();
  });

  test('each repeat increments the count and stamps the time', async () => {
    const agent = await createAgent();
    const attempt = await prisma.aiLeakAttempt.create({
      data: { agentId: agent.id, platform: 'GROK', method: 'BROWSER', riskScore: 0.6 },
    });

    const first = await request(app)
      .patch(`/api/ai-policy/attempt/${attempt.id}/repeat`)
      .set('x-agent-token', agent.token);
    expect(first.status).toBe(200);
    expect(first.body.attempts).toBe(2);
    expect(first.body.lastAttemptAt).not.toBeNull();

    const second = await request(app)
      .patch(`/api/ai-policy/attempt/${attempt.id}/repeat`)
      .set('x-agent-token', agent.token);
    expect(second.body.attempts).toBe(3);
  });

  test('concurrent repeats do not lose an increment', async () => {
    // The agent reports from several monitor threads, and a burst is exactly
    // what this field measures -- a read-modify-write in the route would
    // undercount precisely when the number matters most.
    const agent = await createAgent();
    const attempt = await prisma.aiLeakAttempt.create({
      data: { agentId: agent.id, platform: 'GROK', method: 'BROWSER', riskScore: 0.6 },
    });

    await Promise.all(
      Array.from({ length: 10 }, () =>
        request(app)
          .patch(`/api/ai-policy/attempt/${attempt.id}/repeat`)
          .set('x-agent-token', agent.token)),
    );

    const row = await prisma.aiLeakAttempt.findUnique({ where: { id: attempt.id } });
    expect(row.attempts).toBe(11);
  });
});
