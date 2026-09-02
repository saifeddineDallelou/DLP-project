const request = require('supertest');
const app = require('../src/app');
const { prisma, resetDb, createUser, authHeader, createAgent } = require('./helpers');

afterEach(resetDb);
afterAll(() => prisma.$disconnect());

// The point of the scoring rewrite: the baseline that recompute works to
// produce is now actually READ when judging today, and a declared peer group
// gives a second reference point for when the user's own baseline cannot be
// trusted. Endpoint-level coverage; the arithmetic itself is pinned down in
// ueba-scoring.test.js.

async function baselineFor(userId, overrides = {}) {
  return prisma.userBehaviorBaseline.create({
    data: {
      userId,
      avgDailyFiles: 10,
      avgDailyVolumeMB: 100,
      avgWorkingHourStart: 9,
      avgWorkingHourEnd: 17,
      avgUsbFrequency: 0,
      activeDaysObserved: 30,
      riskScore: 0,
      lastUpdated: new Date(),
      ...overrides,
    },
  });
}

async function fileEvent(agentId, userId, metadata, timestamp) {
  return prisma.behaviorEvent.create({
    data: {
      agentId,
      userId,
      eventType: 'FILE_ACCESS',
      metadata,
      ...(timestamp ? { timestamp } : {}),
    },
  });
}

describe('deviation scoring against the user own baseline', () => {
  test('activity within the baseline scores no deviation at all', async () => {
    const { user } = await createUser();
    const agent = await createAgent();
    await baselineFor(user.id);
    await fileEvent(agent.id, user.id, { count: 8, sizeMB: 80, hour: 11 });

    const res = await request(app)
      .get(`/api/ueba/risk-score/${user.id}`).set('Authorization', authHeader(user));

    expect(res.status).toBe(200);
    expect(res.body.deviationScore).toBe(0);
    expect(res.body.riskLevel).toBe('LOW');
  });

  test('volume far above the baseline drives the score and reports the ratio', async () => {
    const { user } = await createUser();
    const agent = await createAgent();
    await baselineFor(user.id);
    await fileEvent(agent.id, user.id, { count: 250, sizeMB: 8000, hour: 11 });

    const res = await request(app)
      .get(`/api/ueba/risk-score/${user.id}`).set('Authorization', authHeader(user));

    expect(res.status).toBe(200);
    expect(res.body.components.volume.ratio).toBeCloseTo(80, 1);   // 8000 / 100
    expect(res.body.components.volume.signal).toBe(1);
    expect(res.body.components.files.ratio).toBeCloseTo(25, 1);    // 250 / 10
    expect(res.body.riskLevel).toBe('HIGH');
  });

  test('the SAME activity is judged differently for two people', async () => {
    // The property a fixed global threshold cannot express, and the reason
    // per-user baselines exist at all.
    const { user: clerk } = await createUser();
    const { user: engineer } = await createUser();
    const agent = await createAgent();

    await baselineFor(clerk.id, { avgDailyFiles: 5, avgDailyVolumeMB: 20 });
    await baselineFor(engineer.id, { avgDailyFiles: 800, avgDailyVolumeMB: 4000 });

    await fileEvent(agent.id, clerk.id, { count: 300, sizeMB: 1500, hour: 11 });
    await fileEvent(agent.id, engineer.id, { count: 300, sizeMB: 1500, hour: 11 });

    const clerkRes = await request(app)
      .get(`/api/ueba/risk-score/${clerk.id}`).set('Authorization', authHeader(clerk));
    const engRes = await request(app)
      .get(`/api/ueba/risk-score/${engineer.id}`).set('Authorization', authHeader(engineer));

    expect(clerkRes.body.riskLevel).toBe('HIGH');
    expect(engRes.body.deviationScore).toBe(0);
    expect(clerkRes.body.liveRiskScore).toBeGreaterThan(engRes.body.liveRiskScore);
  });

  test('activity outside the working-hour window contributes', async () => {
    const { user } = await createUser();
    const agent = await createAgent();
    await baselineFor(user.id);
    await fileEvent(agent.id, user.id, { count: 5, sizeMB: 10, hour: 3 });

    const res = await request(app)
      .get(`/api/ueba/risk-score/${user.id}`).set('Authorization', authHeader(user));

    expect(res.body.components.hours.signal).toBe(1);
    expect(res.body.components.hours.observed).toBe(1);
  });

  test('the response carries a per-metric breakdown, not just a number', async () => {
    const { user } = await createUser();
    const agent = await createAgent();
    await baselineFor(user.id);
    await fileEvent(agent.id, user.id, { count: 50, sizeMB: 500, hour: 11 });

    const res = await request(app)
      .get(`/api/ueba/risk-score/${user.id}`).set('Authorization', authHeader(user));

    for (const key of ['volume', 'files', 'hours', 'usb']) {
      expect(res.body.components[key]).toBeDefined();
      expect(typeof res.body.components[key].signal).toBe('number');
    }
    expect(res.body).toHaveProperty('deviationScore');
    expect(res.body).toHaveProperty('eventBonus');
  });
});

describe('peer-group scoring', () => {
  test('a poisoned self-baseline is still caught by the peer comparison', async () => {
    // The failure mode this exists for: someone recomputed this user's
    // baseline over a window that made their exfiltration look routine, so
    // self-deviation goes quiet. The peer median did not move.
    const { user: suspect } = await createUser();
    const { user: peerA } = await createUser();
    const { user: peerB } = await createUser();
    const agent = await createAgent();

    await baselineFor(suspect.id, { department: 'Engineering', avgDailyVolumeMB: 8000, avgDailyFiles: 300 });
    await baselineFor(peerA.id, { department: 'Engineering', avgDailyVolumeMB: 200, avgDailyFiles: 15 });
    await baselineFor(peerB.id, { department: 'Engineering', avgDailyVolumeMB: 240, avgDailyFiles: 18 });

    await fileEvent(agent.id, suspect.id, { count: 300, sizeMB: 8000, hour: 11 });

    const res = await request(app)
      .get(`/api/ueba/risk-score/${suspect.id}`).set('Authorization', authHeader(suspect));

    expect(res.status).toBe(200);
    // Against their own poisoned baseline: entirely unremarkable.
    expect(res.body.components.volume.signal).toBe(0);
    // Against Engineering's median of 220 MB: far past the full-signal point.
    expect(res.body.components.volume.peerSignal).toBe(1);
    expect(res.body.peerGroup).toMatchObject({ department: 'Engineering', peerCount: 2 });
    expect(res.body.riskLevel).toBe('HIGH');
  });

  test('the user is excluded from their own peer median', async () => {
    const { user } = await createUser();
    const { user: peer } = await createUser();
    await baselineFor(user.id, { department: 'Finance', avgDailyVolumeMB: 9000 });
    await baselineFor(peer.id, { department: 'Finance', avgDailyVolumeMB: 50 });

    const res = await request(app)
      .get(`/api/ueba/risk-score/${user.id}`).set('Authorization', authHeader(user));

    // The peer median is the peer's 50, not a blend including the suspect's own
    // 9000 -- otherwise a single outlier partly defines the group it is being
    // measured against.
    expect(res.body.components.volume.peerBaseline).toBe(50);
    expect(res.body.peerGroup.peerCount).toBe(1);
  });

  test('a user with no department is scored self-relative only', async () => {
    const { user } = await createUser();
    await baselineFor(user.id);

    const res = await request(app)
      .get(`/api/ueba/risk-score/${user.id}`).set('Authorization', authHeader(user));

    expect(res.body.peerGroup).toBeNull();
    expect(res.body.components.volume.peerSignal).toBeNull();
  });

  test('a lone member of a department degrades quietly rather than erroring', async () => {
    const { user } = await createUser();
    await baselineFor(user.id, { department: 'Legal' });

    const res = await request(app)
      .get(`/api/ueba/risk-score/${user.id}`).set('Authorization', authHeader(user));

    expect(res.status).toBe(200);
    expect(res.body.peerGroup).toMatchObject({ department: 'Legal', peerCount: 0 });
    expect(res.body.components.volume.peerSignal).toBeNull();
  });

  test('members of a different department are not treated as peers', async () => {
    const { user } = await createUser();
    const { user: other } = await createUser();
    await baselineFor(user.id, { department: 'Finance', avgDailyVolumeMB: 100 });
    await baselineFor(other.id, { department: 'Engineering', avgDailyVolumeMB: 5000 });

    const res = await request(app)
      .get(`/api/ueba/risk-score/${user.id}`).set('Authorization', authHeader(user));

    expect(res.body.peerGroup.peerCount).toBe(0);
  });
});

describe('recompute: median and department handling', () => {
  test('the median ignores a single outlier day', async () => {
    const { user: analyst } = await createUser({ role: 'ADMIN' });
    const { user: target } = await createUser();
    const agent = await createAgent();

    // Four ordinary days and one 8 GB day. A mean would report ~1608 MB/day.
    const perDay = [10, 12, 11, 9, 8000];
    for (let i = 0; i < perDay.length; i++) {
      await fileEvent(
        agent.id, target.id,
        { count: 5, sizeMB: perDay[i], hour: 10 },
        new Date(Date.now() - i * 24 * 60 * 60 * 1000),
      );
    }

    const res = await request(app)
      .post(`/api/ueba/baseline/${target.id}/recompute`)
      .set('Authorization', authHeader(analyst));

    expect(res.status).toBe(200);
    expect(res.body.computedFrom.activeDays).toBe(5);
    expect(res.body.avgDailyVolumeMB).toBe(11);
  });

  test('inactive days are excluded rather than counted as zero', async () => {
    const { user: analyst } = await createUser({ role: 'ADMIN' });
    const { user: target } = await createUser();
    const agent = await createAgent();

    // Two active days inside a 30-day window. Counting the other 28 as zero
    // would drag the baseline to near nothing and make an ordinary day look
    // anomalous.
    await fileEvent(agent.id, target.id, { count: 5, sizeMB: 100, hour: 10 }, new Date());
    await fileEvent(
      agent.id, target.id, { count: 5, sizeMB: 100, hour: 10 },
      new Date(Date.now() - 24 * 60 * 60 * 1000),
    );

    const res = await request(app)
      .post(`/api/ueba/baseline/${target.id}/recompute?days=30`)
      .set('Authorization', authHeader(analyst));

    expect(res.body.computedFrom.activeDays).toBe(2);
    expect(res.body.avgDailyVolumeMB).toBe(100);   // not 100*2/30 = 6.67
  });

  test('preserves a declared department it was not asked to change', async () => {
    const { user: analyst } = await createUser({ role: 'ADMIN' });
    const { user: target } = await createUser();
    const agent = await createAgent();
    await baselineFor(target.id, { department: 'Engineering' });
    await fileEvent(agent.id, target.id, { count: 5, sizeMB: 10, hour: 10 });

    const res = await request(app)
      .post(`/api/ueba/baseline/${target.id}/recompute`)
      .set('Authorization', authHeader(analyst));

    expect(res.status).toBe(200);
    expect(res.body.department).toBe('Engineering');
  });

  test('sets a department when one is supplied', async () => {
    const { user: analyst } = await createUser({ role: 'ADMIN' });
    const { user: target } = await createUser();
    const agent = await createAgent();
    await fileEvent(agent.id, target.id, { count: 5, sizeMB: 10, hour: 10 });

    const res = await request(app)
      .post(`/api/ueba/baseline/${target.id}/recompute?department=Finance`)
      .set('Authorization', authHeader(analyst));

    expect(res.status).toBe(200);
    expect(res.body.department).toBe('Finance');
  });

  test('POST /baseline leaves the department alone when the field is omitted', async () => {
    const { user: analyst } = await createUser({ role: 'ADMIN' });
    const { user: target } = await createUser();
    await baselineFor(target.id, { department: 'Engineering' });

    const res = await request(app)
      .post('/api/ueba/baseline')
      .set('Authorization', authHeader(analyst))
      .send({ userId: target.id, avgDailyFiles: 50, avgDailyVolumeMB: 500 });

    expect(res.status).toBe(201);
    expect(res.body.department).toBe('Engineering');
  });
});
