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

describe('POST /api/ueba/baseline/:userId/recompute', () => {
  test('requires ADMIN/ANALYST role', async () => {
    const { user } = await createUser({ role: 'VIEWER' });
    const res = await request(app)
      .post(`/api/ueba/baseline/${user.id}/recompute`)
      .set('Authorization', authHeader(user));
    expect(res.status).toBe(403);
  });

  test('404s when the user has no behavior events at all', async () => {
    const { user: analyst } = await createUser({ role: 'ADMIN' });
    const { user: target } = await createUser();
    const res = await request(app)
      .post(`/api/ueba/baseline/${target.id}/recompute`)
      .set('Authorization', authHeader(analyst));
    expect(res.status).toBe(404);
  });

  test('computes a baseline for an OS username with no matching dashboard User account', async () => {
    // The live agent reports BehaviorEvent.userId as the Windows username
    // (e.g. "MMD"), not a dashboard login account -- userId is a free
    // string, not a foreign key to users, so this must work.
    const { user: analyst } = await createUser({ role: 'ADMIN' });
    const agent = await createAgent();
    await prisma.behaviorEvent.create({
      data: { agentId: agent.id, userId: 'MMD', eventType: 'FILE_ACCESS', metadata: { count: 5, hour: 10 } },
    });

    const res = await request(app)
      .post('/api/ueba/baseline/MMD/recompute')
      .set('Authorization', authHeader(analyst));

    expect(res.status).toBe(200);
    expect(res.body.userId).toBe('MMD');
  });

  test('computes avgDailyFiles and avgUsbFrequency from real event history', async () => {
    const { user: analyst } = await createUser({ role: 'ADMIN' });
    const { user: target } = await createUser();
    const agent = await createAgent();

    await prisma.behaviorEvent.create({
      data: { agentId: agent.id, userId: target.id, eventType: 'FILE_ACCESS', metadata: { count: 20, hour: 10 } },
    });
    await prisma.behaviorEvent.create({
      data: { agentId: agent.id, userId: target.id, eventType: 'AFTER_HOURS_ACCESS', metadata: { count: 10, hour: 22 } },
    });
    await prisma.behaviorEvent.create({
      data: { agentId: agent.id, userId: target.id, eventType: 'USB_INSERT', metadata: {} },
    });

    const res = await request(app)
      .post(`/api/ueba/baseline/${target.id}/recompute?days=10`)
      .set('Authorization', authHeader(analyst));

    expect(res.status).toBe(200);
    expect(res.body.avgDailyFiles).toBeCloseTo(3.0, 3);   // (20 + 10 files) / 10 days
    expect(res.body.avgUsbFrequency).toBeCloseTo(0.1, 3); // 1 insert / 10 days
    expect(res.body.computedFrom.eventCount).toBe(3);
  });

  test('derives working hours from the 10th/90th percentile of observed activity', async () => {
    const { user: analyst } = await createUser({ role: 'ADMIN' });
    const { user: target } = await createUser();
    const agent = await createAgent();

    for (const hour of [8, 9, 10, 11, 17, 18, 19]) {
      await prisma.behaviorEvent.create({
        data: { agentId: agent.id, userId: target.id, eventType: 'FILE_ACCESS', metadata: { count: 1, hour } },
      });
    }

    const res = await request(app)
      .post(`/api/ueba/baseline/${target.id}/recompute`)
      .set('Authorization', authHeader(analyst));

    expect(res.status).toBe(200);
    // 7 samples sorted [8,9,10,11,17,18,19] -- floor(0.1*6)=0 -> 8, floor(0.9*6)=5 -> 18
    expect(res.body.avgWorkingHourStart).toBe(8);
    expect(res.body.avgWorkingHourEnd).toBe(18);
  });

  test('computes avgDailyVolumeMB from FILE_ACCESS sizeMB metadata', async () => {
    const { user: analyst } = await createUser({ role: 'ADMIN' });
    const { user: target } = await createUser();
    const agent = await createAgent();
    await prisma.behaviorEvent.create({
      data: { agentId: agent.id, userId: target.id, eventType: 'FILE_ACCESS', metadata: { count: 5, sizeMB: 20, hour: 10 } },
    });

    const res = await request(app)
      .post(`/api/ueba/baseline/${target.id}/recompute?days=10`)
      .set('Authorization', authHeader(analyst));

    expect(res.status).toBe(200);
    expect(res.body.avgDailyVolumeMB).toBeCloseTo(2.0, 3); // 20 MB / 10 days
  });

  test('includes LARGE_FILE_TRANSFER volume without double-counting FILE_ACCESS', async () => {
    const { user: analyst } = await createUser({ role: 'ADMIN' });
    const { user: target } = await createUser();
    const agent = await createAgent();
    await prisma.behaviorEvent.create({
      data: { agentId: agent.id, userId: target.id, eventType: 'FILE_ACCESS', metadata: { count: 5, sizeMB: 20, hour: 10 } },
    });
    await prisma.behaviorEvent.create({
      data: { agentId: agent.id, userId: target.id, eventType: 'LARGE_FILE_TRANSFER', metadata: { filename: 'archive.zip', sizeMB: 150, hour: 14 } },
    });

    const res = await request(app)
      .post(`/api/ueba/baseline/${target.id}/recompute?days=10`)
      .set('Authorization', authHeader(analyst));

    expect(res.status).toBe(200);
    expect(res.body.avgDailyVolumeMB).toBeCloseTo(17.0, 3); // (20 + 150) MB / 10 days
    expect(res.body.computedFrom.largeFileTransfers).toBe(1);
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

  test('large file transfers contribute to the live risk score', async () => {
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
      data: { agentId: agent.id, userId: user.id, eventType: 'LARGE_FILE_TRANSFER', metadata: { sizeMB: 150 } },
    });

    const res = await request(app)
      .get(`/api/ueba/risk-score/${user.id}`)
      .set('Authorization', authHeader(user));

    expect(res.status).toBe(200);
    // 0.2 base + 0.15 (1 large file transfer) = 0.35
    expect(res.body.liveRiskScore).toBeCloseTo(0.35, 3);
    expect(res.body.last24h.largeFileTransfers).toBe(1);
  });

  test('handles missing baseline gracefully', async () => {
    const { user } = await createUser();
    const res = await request(app)
      .get(`/api/ueba/risk-score/${user.id}`)
      .set('Authorization', authHeader(user));

    expect(res.status).toBe(200);
    expect(res.body.baselineExists).toBe(false);
    expect(res.body.liveRiskScore).toBe(0);
    expect(res.body.baseline).toBeNull();
  });

  test('includes the computed baseline stats (avgDailyFiles, working hours, USB) in the response', async () => {
    const { user } = await createUser();
    await prisma.userBehaviorBaseline.create({
      data: {
        userId: user.id, avgDailyFiles: 3.33, avgDailyVolumeMB: 0,
        avgWorkingHourStart: 8, avgWorkingHourEnd: 19, avgUsbFrequency: 0.1,
        riskScore: 0, lastUpdated: new Date(),
      },
    });

    const res = await request(app)
      .get(`/api/ueba/risk-score/${user.id}`)
      .set('Authorization', authHeader(user));

    expect(res.status).toBe(200);
    expect(res.body.baseline).toMatchObject({
      avgDailyFiles: 3.33, avgDailyVolumeMB: 0, avgWorkingHourStart: 8, avgWorkingHourEnd: 19, avgUsbFrequency: 0.1,
    });
  });
});
