const request = require('supertest');
const app = require('../src/app');
const { prisma, resetDb, createUser, authHeader } = require('./helpers');

afterEach(async () => {
  await resetDb();
  jest.restoreAllMocks();
});
afterAll(() => prisma.$disconnect());

function mockUpstream(body, { ok = true, status = 200 } = {}) {
  jest.spyOn(global, 'fetch').mockResolvedValue({
    ok,
    status,
    json: async () => body,
    text: async () => JSON.stringify(body),
  });
}

describe('POST /api/classify', () => {
  test('requires auth', async () => {
    const res = await request(app).post('/api/classify').send({ content: 'hi' });
    expect(res.status).toBe(401);
  });

  test('requires content', async () => {
    const { user } = await createUser();
    const res = await request(app)
      .post('/api/classify')
      .set('Authorization', authHeader(user))
      .send({});
    expect(res.status).toBe(400);
  });

  test('maps high risk score to RESTRICTED/BLOCK', async () => {
    const { user } = await createUser();
    mockUpstream({
      risk_score: 0.9,
      sensitive: true,
      detections: [{ type: 'SSN', value: '123-45-6789', rule: 'ssn', confidence: 0.95 }],
      evidence_excerpt: 'SSN: 123-45-6789',
    });

    const res = await request(app)
      .post('/api/classify')
      .set('Authorization', authHeader(user))
      .send({ content: 'my ssn is 123-45-6789', channel: 'CLIPBOARD' });

    expect(res.status).toBe(200);
    expect(res.body.classification).toBe('RESTRICTED');
    expect(res.body.recommendedAction).toBe('BLOCK');
    expect(res.body.categories).toEqual(['SSN']);
    expect(res.body.channel).toBe('CLIPBOARD');
  });

  test('maps mid risk score to CONFIDENTIAL/ALERT', async () => {
    const { user } = await createUser();
    mockUpstream({ risk_score: 0.6, sensitive: true, detections: [], evidence_excerpt: '' });

    const res = await request(app)
      .post('/api/classify')
      .set('Authorization', authHeader(user))
      .send({ content: 'somewhat sensitive' });

    expect(res.body.classification).toBe('CONFIDENTIAL');
    expect(res.body.recommendedAction).toBe('ALERT');
  });

  test('maps zero risk score to PUBLIC/ALLOW', async () => {
    const { user } = await createUser();
    mockUpstream({ risk_score: 0, sensitive: false, detections: [], evidence_excerpt: '' });

    const res = await request(app)
      .post('/api/classify')
      .set('Authorization', authHeader(user))
      .send({ content: 'hello world' });

    expect(res.body.classification).toBe('PUBLIC');
    expect(res.body.recommendedAction).toBe('ALLOW');
  });

  test('returns 503 when the classifier service is unreachable', async () => {
    const { user } = await createUser();
    jest.spyOn(global, 'fetch').mockRejectedValue(new Error('ECONNREFUSED'));

    const res = await request(app)
      .post('/api/classify')
      .set('Authorization', authHeader(user))
      .send({ content: 'hello' });

    expect(res.status).toBe(503);
  });

  test('returns 502 when the classifier responds with an error', async () => {
    const { user } = await createUser();
    mockUpstream({ error: 'boom' }, { ok: false, status: 500 });

    const res = await request(app)
      .post('/api/classify')
      .set('Authorization', authHeader(user))
      .send({ content: 'hello' });

    expect(res.status).toBe(502);
  });
});
