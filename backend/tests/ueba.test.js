const request = require('supertest');
const app = require('../src/app');
const { prisma, resetDb, createUser, authHeader, createAgent } = require('./helpers');

afterEach(resetDb);
afterAll(() => prisma.$disconnect());

describe('GET/POST /api/ueba/baseline', () => {
  test('GET requires auth', async () => {
    const res = await request(app).get('/api/ueba/baseline');
    expect(res.status).toBe(401);
  });

  test('non-privileged user can only fetch their own baseline', async () => {
    const { user: viewer } = await createUser({ role: 'VIEWER' });
    const { user: other } = await createUser({ role: 'VIEWER' });
    await prisma.userBehaviorBaseline.create({
      data: {
        userId: other.id, avgDailyFiles: 10, avgDailyVolumeMB: 5,
        avgWorkingHourStart: 9, avgWorkingHourEnd: 17, avgUsbFrequency: 0,
        riskScore: 0.1, lastUpdated: new Date(),
      },
    });

    const res = await request(app)
      .get(`/api/ueba/baseline?userId=${other.id}`)
      .set('Authorization', authHeader(viewer));

    // VIEWER's userId query param is ignored — they only ever see their own (missing) baseline
    expect(res.status).toBe(404);
  });

  test('ANALYST can query another user baseline via userId param', async () => {
    const { user: analyst } = await createUser({ role: 'ANALYST' });
    const { user: target } = await createUser();
    await prisma.userBehaviorBaseline.create({
      data: {
        userId: target.id, avgDailyFiles: 10, avgDailyVolumeMB: 5,
        avgWorkingHourStart: 9, avgWorkingHourEnd: 17, avgUsbFrequency: 0,
        riskScore: 0.1, lastUpdated: new Date(),
      },
    });

    const res = await request(app)
      .get(`/api/ueba/baseline?userId=${target.id}`)
      .set('Authorization', authHeader(analyst));

    expect(res.status).toBe(200);
    expect(res.body.userId).toBe(target.id);
  });

  test('POST requires ADMIN/ANALYST role', async () => {
    const { user } = await createUser({ role: 'VIEWER' });
    const res = await request(app)
      .post('/api/ueba/baseline')
      .set('Authorization', authHeader(user))
      .send({ userId: user.id, avgDailyFiles: 1, avgDailyVolumeMB: 1 });
    expect(res.status).toBe(403);
  });

  test('POST upserts a baseline', async () => {
    const { user: analyst } = await createUser({ role: 'ADMIN' });
    const { user: target } = await createUser();

    const res = await request(app)
      .post('/api/ueba/baseline')
      .set('Authorization', authHeader(analyst))
      .send({ userId: target.id, avgDailyFiles: 100, avgDailyVolumeMB: 20 });

    expect(res.status).toBe(201);
    expect(res.body.avgDailyFiles).toBe(100);
    expect(res.body.avgWorkingHourStart).toBe(9); // default
  });
});

describe('GET/POST /api/ueba/events', () => {
  test('POST validates required fields', async () => {
    const res = await request(app).post('/api/ueba/events').send({});
    expect(res.status).toBe(400);
  });

  test('POST accepts agent-token auth', async () => {
    const agent = await createAgent();
    const res = await request(app)
      .post('/api/ueba/events')
      .set('x-agent-token', agent.token)
      .send({ agentId: agent.id, userId: 'someuser', eventType: 'USB_INSERT', metadata: { size: 1 } });

    expect(res.status).toBe(201);
    expect(res.body.eventType).toBe('USB_INSERT');
  });

  test('POST rejects missing auth', async () => {
    const agent = await createAgent();
    const res = await request(app)
      .post('/api/ueba/events')
      .send({ agentId: agent.id, userId: 'someuser', eventType: 'USB_INSERT' });
    expect(res.status).toBe(401);
  });

  test('GET requires auth and filters/paginates', async () => {
    const agent = await createAgent();
    await prisma.behaviorEvent.create({
      data: { agentId: agent.id, userId: 'u1', eventType: 'FILE_ACCESS', metadata: {} },
    });
    const { user } = await createUser();

    const res = await request(app)
      .get('/api/ueba/events?userId=u1')
      .set('Authorization', authHeader(user));

    expect(res.status).toBe(200);
    expect(res.body.total).toBe(1);
  });
});

describe('GET /api/ueba/risk-score/:userId', () => {
  test('computes live risk score from recent anomalous events', async () => {
    const { user } = await createUser();
    const agent = await createAgent();
    await prisma.userBehaviorBaseline.create({
      data: {
        userId: user.id, avgDailyFiles: 10, avgDailyVolumeMB: 5,
        avgWorkingHourStart: 9, avgWorkingHourEnd: 17, avgUsbFrequency: 0,
        riskScore: 0.2, lastUpdated: new Date(),
      },
    });
    await prisma.behaviorEvent.create({
      data: { agentId: agent.id, userId: user.id, eventType: 'AFTER_HOURS_ACCESS', metadata: {} },
    });
    await prisma.behaviorEvent.create({
      data: { agentId: agent.id, userId: user.id, eventType: 'USB_INSERT', metadata: {} },
    });

    const res = await request(app)
      .get(`/api/ueba/risk-score/${user.id}`)
      .set('Authorization', authHeader(user));

    expect(res.status).toBe(200);
    // 0.2 base + 0.1 (1 after-hours) + 0.05 (1 usb) = 0.35
    expect(res.body.liveRiskScore).toBeCloseTo(0.35, 3);
    expect(res.body.riskLevel).toBe('LOW');
    expect(res.body.baselineExists).toBe(true);
  });

  test('handles missing baseline gracefully', async () => {
    const { user } = await createUser();
    const res = await request(app)
      .get(`/api/ueba/risk-score/${user.id}`)
      .set('Authorization', authHeader(user));

    expect(res.status).toBe(200);
    expect(res.body.baselineExists).toBe(false);
    expect(res.body.liveRiskScore).toBe(0);
  });
});
