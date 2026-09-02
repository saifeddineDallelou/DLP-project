const request = require('supertest');
const app = require('../src/app');
const { prisma, resetDb, createUser, authHeader, createAgent } = require('./helpers');
const { recomputeBaseline } = require('../src/lib/baseline');

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
    // Median across ACTIVE days, not sum/window. All three events land on the
    // same calendar day, so there is one active day holding 20 + 10 = 30 files
    // and 1 USB insert, and the median of a single value is that value.
    // Previously this was 30/10 = 3.0, which described a day the user never had.
    expect(res.body.avgDailyFiles).toBeCloseTo(30, 3);
    expect(res.body.avgUsbFrequency).toBeCloseTo(1, 3);
    expect(res.body.computedFrom.eventCount).toBe(3);
    expect(res.body.computedFrom.activeDays).toBe(1);
    expect(res.body.computedFrom.statistic).toBe('median-across-active-days');
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
    expect(res.body.avgDailyVolumeMB).toBeCloseTo(20, 3); // one active day holding 20 MB
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
    expect(res.body.avgDailyVolumeMB).toBeCloseTo(170, 3); // one active day holding 20 + 150 MB
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
        activeDaysObserved: 30,
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
    // Neither event carries file/volume metadata, so volume and files sit at
    // zero. The USB insert IS a deviation -- this baseline says the user never
    // uses USB -- but a zero baseline is capped at 0.6, so it cannot decide the
    // score alone: 0.6 x 0.75 dominant floor = 0.45, plus the event bonus
    // (after-hours 0.05 + usb 0.02) = 0.52.
    //
    // MEDIUM is the right answer here. Someone who has never used a USB stick
    // using one after hours is worth a look; it is not on its own a HIGH
    // finding, and treating it as one manufactures false positives on every
    // new starter.
    expect(res.body.liveRiskScore).toBeCloseTo(0.52, 3);
    expect(res.body.riskLevel).toBe('MEDIUM');
    expect(res.body.baselineExists).toBe(true);
    expect(res.body.components.usb.signal).toBeCloseTo(0.6, 3);
    expect(res.body.components.volume.signal).toBe(0);
  });

  test('large file transfers contribute to the live risk score', async () => {
    const { user } = await createUser();
    const agent = await createAgent();
    await prisma.userBehaviorBaseline.create({
      data: {
        userId: user.id, avgDailyFiles: 10, avgDailyVolumeMB: 5,
        avgWorkingHourStart: 9, avgWorkingHourEnd: 17, avgUsbFrequency: 0,
        activeDaysObserved: 30,
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
    // 150 MB against a 5 MB baseline is 30x normal -- far past the 5x full-signal
    // point, so volume contributes its full 0.35 weight. Under the old formula
    // this scored 0.35 regardless of size; a 5 MB transfer and a 150 MB one
    // were indistinguishable.
    expect(res.body.components.volume.ratio).toBeCloseTo(30, 1);
    expect(res.body.components.volume.signal).toBe(1);
    // Volume alone is fully anomalous, so the dominant-signal floor carries it
    // to 0.75, plus the 0.08 large-transfer event bonus = 0.83 -> HIGH.
    expect(res.body.liveRiskScore).toBeCloseTo(0.83, 3);
    expect(res.body.riskLevel).toBe('HIGH');
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

describe('UEBA learning period', () => {
  // The failure this prevents: a freshly deployed agent produces a baseline
  // like "works 12:00-12:00, one file a day". Every ordinary morning after
  // that reads as after-hours, DOMINANT_SIGNAL_FACTOR lets that one metric
  // clear HIGH unaided, and an entire rollout flags on day two -- because on
  // day one the system had never seen anyone work.

  async function thinBaseline(userId, activeDaysObserved) {
    return prisma.userBehaviorBaseline.create({
      data: {
        userId,
        avgDailyFiles: 1,
        avgDailyVolumeMB: 0,
        // The degenerate window a single afternoon of observation produces.
        avgWorkingHourStart: 12,
        avgWorkingHourEnd: 12,
        avgUsbFrequency: 0,
        activeDaysObserved,
        riskScore: 0,
        lastUpdated: new Date(),
      },
    });
  }

  test('a thin baseline reports LEARNING, not a risk band', async () => {
    const { user } = await createUser();
    const agent = await createAgent();
    await thinBaseline(user.id, 1);
    // Ordinary morning activity, well outside the degenerate 12-12 window.
    for (const hour of [9, 9, 10, 10]) {
      await prisma.behaviorEvent.create({
        data: { agentId: agent.id, userId: user.id, eventType: 'FILE_ACCESS',
                metadata: { count: 1, sizeMB: 0, hour } },
      });
    }

    const res = await request(app)
      .get(`/api/ueba/risk-score/${user.id}`)
      .set('Authorization', authHeader(user));

    expect(res.status).toBe(200);
    expect(res.body.riskLevel).toBe('LEARNING');
    expect(res.body.learning).toEqual({
      activeDaysObserved: 1,
      activeDaysRequired: 7,
      hasBaseline: true,
    });
    // No deviation judgement is made at all -- the components that would
    // otherwise report "4 of 4 outside 12-12h" are simply not computed.
    expect(res.body.deviationScore).toBe(0);
    expect(res.body.components).toEqual({});
  });

  test('without the gate the same data would score HIGH', async () => {
    // Pins WHY the gate exists rather than merely that it is there: the exact
    // same events against the exact same numbers, with enough observed days
    // to be trusted, produce a HIGH from the hours metric alone.
    const { user } = await createUser();
    const agent = await createAgent();
    await thinBaseline(user.id, 30);
    for (const hour of [9, 9, 10, 10]) {
      await prisma.behaviorEvent.create({
        data: { agentId: agent.id, userId: user.id, eventType: 'FILE_ACCESS',
                metadata: { count: 1, sizeMB: 0, hour } },
      });
    }

    const res = await request(app)
      .get(`/api/ueba/risk-score/${user.id}`)
      .set('Authorization', authHeader(user));

    expect(res.body.riskLevel).toBe('HIGH');
    expect(res.body.components.hours.signal).toBe(1);
  });

  test('absolute signals still surface during learning', async () => {
    // A large transfer or a PCI-DSS block needs no baseline to be meaningful,
    // so learning withholds the deviation JUDGEMENT, not the facts.
    const { user } = await createUser();
    const agent = await createAgent();
    await thinBaseline(user.id, 1);
    await prisma.behaviorEvent.create({
      data: { agentId: agent.id, userId: user.id, eventType: 'LARGE_FILE_TRANSFER',
              metadata: { sizeMB: 900 } },
    });

    const res = await request(app)
      .get(`/api/ueba/risk-score/${user.id}`)
      .set('Authorization', authHeader(user));

    expect(res.body.riskLevel).toBe('LEARNING');
    expect(res.body.eventBonus).toBeGreaterThan(0);
    expect(res.body.last24h.largeFileTransfers).toBe(1);
  });

  test('a user with no baseline at all is LEARNING with hasBaseline false', async () => {
    const { user } = await createUser();
    const res = await request(app)
      .get(`/api/ueba/risk-score/${user.id}`)
      .set('Authorization', authHeader(user));

    expect(res.body.riskLevel).toBe('LEARNING');
    expect(res.body.learning.hasBaseline).toBe(false);
    expect(res.body.learning.activeDaysObserved).toBe(0);
  });

  test('a baseline predating the field is treated as not yet trusted', async () => {
    // activeDaysObserved defaults to 0 for rows written before it existed. We
    // do not know what they rest on, so they are not trusted until the hourly
    // refresh recomputes them -- the safe direction.
    const { user } = await createUser();
    await prisma.userBehaviorBaseline.create({
      data: {
        userId: user.id, avgDailyFiles: 10, avgDailyVolumeMB: 100,
        avgWorkingHourStart: 9, avgWorkingHourEnd: 17, avgUsbFrequency: 1,
        riskScore: 0, lastUpdated: new Date(),
      },
    });

    const res = await request(app)
      .get(`/api/ueba/risk-score/${user.id}`)
      .set('Authorization', authHeader(user));

    expect(res.body.riskLevel).toBe('LEARNING');
    expect(res.body.learning.activeDaysObserved).toBe(0);
  });

  test('recompute records how many active days it observed', async () => {
    const agent = await createAgent();
    const day = (n, hour) => {
      const d = new Date();
      d.setDate(d.getDate() - n);
      d.setHours(hour, 0, 0, 0);
      return d;
    };
    for (const n of [1, 2, 3]) {
      await prisma.behaviorEvent.create({
        data: { agentId: agent.id, userId: 'counted-user', eventType: 'FILE_ACCESS',
                metadata: { count: 2, sizeMB: 1, hour: 10 }, timestamp: day(n, 10) },
      });
    }

    const b = await recomputeBaseline({ userId: 'counted-user', days: 30 });
    // The count was ALREADY being computed and returned in computedFrom -- it
    // was simply never persisted, so the scorer could not see it.
    expect(b.computedFrom.activeDays).toBe(3);
    expect(b.baseline.activeDaysObserved).toBe(3);
  });
});

describe('working-hours baseline sources', () => {
  // Regression: the baseline collected `hour` only from FILE_ACCESS /
  // AFTER_HOURS_ACCESS, while the scorer collects today's hours from EVERY
  // event type. A user whose activity is mostly clipboard therefore had a
  // window built from a handful of file events and was then judged against
  // all of it -- which is how a real profile ended up with a 12-12h window
  // and read as 86% out-of-hours during an ordinary morning.
  test('clipboard events contribute to the working-hours window', async () => {
    const agent = await createAgent();
    const day = (n, hour) => {
      const d = new Date();
      d.setDate(d.getDate() - n);
      d.setHours(hour, 0, 0, 0);
      return d;
    };

    // One file event at noon, six clipboard events across the morning --
    // the shape that produced the bug.
    await prisma.behaviorEvent.create({
      data: { agentId: agent.id, userId: 'clip-user', eventType: 'FILE_ACCESS',
              metadata: { count: 1, sizeMB: 0, hour: 12 }, timestamp: day(1, 12) },
    });
    for (const [n, hour] of [[1, 9], [1, 9], [2, 9], [2, 10], [3, 10], [3, 10]]) {
      await prisma.behaviorEvent.create({
        data: { agentId: agent.id, userId: 'clip-user', eventType: 'CLIPBOARD_COPY',
                metadata: { count: 1, hour }, timestamp: day(n, hour) },
      });
    }

    const { baseline } = await recomputeBaseline({ userId: 'clip-user', days: 30 });

    // Built from all seven hours, not the single file event: a real window.
    expect(baseline.avgWorkingHourStart).toBe(9);
    expect(baseline.avgWorkingHourEnd).toBeGreaterThan(9);
    expect(baseline.avgWorkingHourStart).not.toBe(baseline.avgWorkingHourEnd);
  });

  test('clipboard events do not inflate the file or volume baseline', async () => {
    // The hour is shared; the counts are not. A clipboard copy is not a file
    // touched and carries no bytes.
    const agent = await createAgent();
    await prisma.behaviorEvent.create({
      data: { agentId: agent.id, userId: 'clip-only', eventType: 'CLIPBOARD_COPY',
              metadata: { count: 5, hour: 10 } },
    });

    const { baseline } = await recomputeBaseline({ userId: 'clip-only', days: 30 });
    expect(baseline.avgDailyFiles).toBe(0);
    expect(baseline.avgDailyVolumeMB).toBe(0);
    expect(baseline.avgWorkingHourStart).toBe(10);
  });
});

describe('policy violations during the learning period', () => {
  // The hole the first version of the learning gate opened: LEARNING replaced
  // the risk band outright, so a 4 GB dump at 3am on a user's SECOND day
  // rendered as a calm grey "building baseline" card -- while eventBonus and
  // priorityBoost sat pegged at their caps and the score read 0.6.
  //
  // Two kinds of detection, only one of which needs a baseline:
  //   anomaly -- "is this unusual FOR YOU"      -> withheld during learning
  //   policy  -- "is this bad regardless"        -> must still fire
  async function thinUser(userId) {
    const agent = await createAgent();
    await prisma.userBehaviorBaseline.create({
      data: {
        userId, avgDailyFiles: 5, avgDailyVolumeMB: 10,
        avgWorkingHourStart: 9, avgWorkingHourEnd: 17, avgUsbFrequency: 0,
        activeDaysObserved: 2, riskScore: 0, lastUpdated: new Date(),
      },
    });
    return agent;
  }

  test('a thin baseline with real policy violations reports a real band', async () => {
    const { user } = await createUser();
    const agent = await thinUser(user.id);
    for (let i = 0; i < 4; i++) {
      await prisma.behaviorEvent.create({
        data: { agentId: agent.id, userId: user.id, eventType: 'AFTER_HOURS_ACCESS',
                metadata: { count: 50, sizeMB: 200, hour: 3 } },
      });
      await prisma.behaviorEvent.create({
        data: { agentId: agent.id, userId: user.id, eventType: 'LARGE_FILE_TRANSFER',
                metadata: { sizeMB: 1200, hour: 3 } },
      });
    }

    const res = await request(app)
      .get(`/api/ueba/risk-score/${user.id}`)
      .set('Authorization', authHeader(user));

    expect(res.body.riskLevel).not.toBe('LEARNING');
    expect(['MEDIUM', 'HIGH']).toContain(res.body.riskLevel);
    // The caveat is still true and still reported alongside the alarm.
    expect(res.body.learning.activeDaysObserved).toBe(2);
    expect(res.body.scoredOn).toBe('policy');
    // The behavioural half really is withheld -- this is not a band derived
    // from a baseline nobody should trust.
    expect(res.body.deviationScore).toBe(0);
    expect(res.body.components).toEqual({});
  });

  test('a quiet user on a thin baseline still reports LEARNING, not LOW', async () => {
    // LOW would be a claim about behaviour, and no behaviour has been learned.
    const { user } = await createUser();
    const agent = await thinUser(user.id);
    await prisma.behaviorEvent.create({
      data: { agentId: agent.id, userId: user.id, eventType: 'FILE_ACCESS',
              metadata: { count: 3, sizeMB: 1, hour: 10 } },
    });

    const res = await request(app)
      .get(`/api/ueba/risk-score/${user.id}`)
      .set('Authorization', authHeader(user));

    expect(res.body.riskLevel).toBe('LEARNING');
    expect(res.body.scoredOn).toBe('policy');
  });

  test('an established user reports that both halves are in play', async () => {
    const { user } = await createUser();
    const agent = await createAgent();
    await prisma.userBehaviorBaseline.create({
      data: {
        userId: user.id, avgDailyFiles: 10, avgDailyVolumeMB: 100,
        avgWorkingHourStart: 9, avgWorkingHourEnd: 17, avgUsbFrequency: 1,
        activeDaysObserved: 30, riskScore: 0, lastUpdated: new Date(),
      },
    });
    await prisma.behaviorEvent.create({
      data: { agentId: agent.id, userId: user.id, eventType: 'FILE_ACCESS',
              metadata: { count: 9, sizeMB: 90, hour: 11 } },
    });

    const res = await request(app)
      .get(`/api/ueba/risk-score/${user.id}`)
      .set('Authorization', authHeader(user));

    expect(res.body.scoredOn).toBe('behaviour+policy');
    expect(res.body.learning).toBeNull();
    expect(res.body.riskLevel).toBe('LOW');
  });
});
