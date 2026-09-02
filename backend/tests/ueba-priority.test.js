const request = require('supertest');
const app = require('../src/app');
const {
  priorityBoost,
  PRIORITY_SEVERITY_WEIGHTS,
  PRIORITY_BOOST_CAP,
} = require('../src/lib/ueba-scoring');
const {
  prisma, resetDb, createUser, authHeader, createAgent, createPolicy,
} = require('./helpers');

afterEach(resetDb);
afterAll(() => prisma.$disconnect());

// A deviation score says how MUCH moved. It cannot say whether what moved
// mattered -- 500 MB of build artefacts and 500 MB of cardholder data deviate
// identically. The classifier already tags every detection with a compliance
// rule and the resolved policy carries a severity; this is that information
// finally reaching the risk score.

describe('priorityBoost (unit)', () => {
  test('is zero with nothing to weigh', () => {
    expect(priorityBoost([]).boost).toBe(0);
    expect(priorityBoost(undefined).boost).toBe(0);
    expect(priorityBoost([null, undefined]).boost).toBe(0);
  });

  test('weights by severity', () => {
    expect(priorityBoost([{ severity: 'LOW' }]).boost).toBe(PRIORITY_SEVERITY_WEIGHTS.LOW);
    expect(priorityBoost([{ severity: 'CRITICAL' }]).boost).toBe(PRIORITY_SEVERITY_WEIGHTS.CRITICAL);
  });

  test('accumulates across findings', () => {
    const r = priorityBoost([{ severity: 'MEDIUM' }, { severity: 'MEDIUM' }]);
    expect(r.boost).toBeCloseTo(PRIORITY_SEVERITY_WEIGHTS.MEDIUM * 2, 5);
  });

  test('caps so sensitivity sharpens a score rather than replacing it', () => {
    const many = Array.from({ length: 50 }, () => ({ severity: 'CRITICAL' }));
    expect(priorityBoost(many).boost).toBe(PRIORITY_BOOST_CAP);
  });

  test('the cap alone cannot reach the HIGH band', () => {
    expect(PRIORITY_BOOST_CAP).toBeLessThan(0.7);
  });

  test('reports which compliance rules drove it, deduplicated', () => {
    const r = priorityBoost([
      { severity: 'HIGH', rule: 'PCI-DSS' },
      { severity: 'HIGH', rule: 'PCI-DSS' },
      { severity: 'LOW', rule: 'GDPR' },
    ]);
    expect(r.rules).toEqual(['GDPR', 'PCI-DSS']);
    expect(r.bySeverity).toEqual({ HIGH: 2, LOW: 1 });
  });

  test('ignores a finding with an unrecognised severity rather than throwing', () => {
    expect(priorityBoost([{ severity: 'NONSENSE' }]).boost).toBe(0);
  });
});

describe('GET /api/ueba/risk-score/:userId — priority content', () => {
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

  test('an incident on the user\'s endpoint raises the score', async () => {
    const { user } = await createUser();
    const agent = await createAgent();
    const policy = await createPolicy({
      conditions: { complianceRule: 'PCI-DSS', minRiskScore: 0.7 },
    });
    await baselineFor(user.id);
    await prisma.behaviorEvent.create({
      data: {
        agentId: agent.id, userId: user.id, eventType: 'FILE_ACCESS',
        metadata: { count: 5, sizeMB: 50, hour: 11 },
      },
    });
    await prisma.incident.create({
      data: { agentId: agent.id, policyId: policy.id, channel: 'CLIPBOARD', severity: 'CRITICAL' },
    });

    const res = await request(app)
      .get(`/api/ueba/risk-score/${user.id}`).set('Authorization', authHeader(user));

    expect(res.status).toBe(200);
    expect(res.body.priorityBoost).toBeCloseTo(PRIORITY_SEVERITY_WEIGHTS.CRITICAL, 3);
    expect(res.body.priorityRules).toContain('PCI-DSS');
    expect(res.body.prioritySeverities).toMatchObject({ CRITICAL: 1 });
  });

  test('identical activity scores higher when sensitive data was involved', async () => {
    // The whole point: same volume, same files, same hours -- different data.
    const { user: plain } = await createUser();
    const { user: sensitive } = await createUser();
    const agentA = await createAgent();
    const agentB = await createAgent();
    const policy = await createPolicy({
      severity: 'CRITICAL',
      conditions: { complianceRule: 'HIPAA' },
    });

    await baselineFor(plain.id);
    await baselineFor(sensitive.id);

    for (const [u, a] of [[plain, agentA], [sensitive, agentB]]) {
      await prisma.behaviorEvent.create({
        data: {
          agentId: a.id, userId: u.id, eventType: 'FILE_ACCESS',
          metadata: { count: 40, sizeMB: 400, hour: 11 },
        },
      });
    }
    await prisma.incident.create({
      data: { agentId: agentB.id, policyId: policy.id, channel: 'CLIPBOARD', severity: 'CRITICAL' },
    });

    const plainRes = await request(app)
      .get(`/api/ueba/risk-score/${plain.id}`).set('Authorization', authHeader(plain));
    const sensRes = await request(app)
      .get(`/api/ueba/risk-score/${sensitive.id}`).set('Authorization', authHeader(sensitive));

    expect(plainRes.body.deviationScore).toBeCloseTo(sensRes.body.deviationScore, 3);
    expect(sensRes.body.liveRiskScore).toBeGreaterThan(plainRes.body.liveRiskScore);
    expect(plainRes.body.priorityBoost).toBe(0);
  });

  test('a blocked AI leak attempt inherits its policy severity', async () => {
    const { user } = await createUser();
    const agent = await createAgent();
    const policy = await createPolicy({
      severity: 'HIGH',
      conditions: { complianceRule: 'GDPR' },
    });
    await baselineFor(user.id);
    await prisma.behaviorEvent.create({
      data: {
        agentId: agent.id, userId: user.id, eventType: 'CLIPBOARD_COPY',
        metadata: { hour: 11 },
      },
    });
    await prisma.aiLeakAttempt.create({
      data: {
        agentId: agent.id, policyId: policy.id,
        platform: 'OPENAI_CHATGPT', method: 'CLIPBOARD', riskScore: 0.9,
      },
    });

    const res = await request(app)
      .get(`/api/ueba/risk-score/${user.id}`).set('Authorization', authHeader(user));

    expect(res.body.priorityBoost).toBeCloseTo(PRIORITY_SEVERITY_WEIGHTS.HIGH, 3);
    expect(res.body.priorityRules).toContain('GDPR');
  });

  test('an AI attempt with no linked policy is skipped, not guessed at', async () => {
    // Attempts recorded before the policyId column existed have no policy.
    const { user } = await createUser();
    const agent = await createAgent();
    await baselineFor(user.id);
    await prisma.behaviorEvent.create({
      data: { agentId: agent.id, userId: user.id, eventType: 'CLIPBOARD_COPY', metadata: { hour: 11 } },
    });
    await prisma.aiLeakAttempt.create({
      data: { agentId: agent.id, platform: 'OPENAI_CHATGPT', method: 'CLIPBOARD', riskScore: 0.9 },
    });

    const res = await request(app)
      .get(`/api/ueba/risk-score/${user.id}`).set('Authorization', authHeader(user));

    expect(res.status).toBe(200);
    expect(res.body.priorityBoost).toBe(0);
  });

  test('incidents on an endpoint the user was not active on are ignored', async () => {
    const { user } = await createUser();
    const ownAgent = await createAgent();
    const otherAgent = await createAgent();
    const policy = await createPolicy({ conditions: { complianceRule: 'PCI-DSS' } });
    await baselineFor(user.id);
    await prisma.behaviorEvent.create({
      data: {
        agentId: ownAgent.id, userId: user.id, eventType: 'FILE_ACCESS',
        metadata: { count: 5, sizeMB: 50, hour: 11 },
      },
    });
    await prisma.incident.create({
      data: { agentId: otherAgent.id, policyId: policy.id, channel: 'CLIPBOARD', severity: 'CRITICAL' },
    });

    const res = await request(app)
      .get(`/api/ueba/risk-score/${user.id}`).set('Authorization', authHeader(user));

    expect(res.body.priorityBoost).toBe(0);
  });

  test('a user with no events at all has no priority boost', async () => {
    const { user } = await createUser();
    await baselineFor(user.id);

    const res = await request(app)
      .get(`/api/ueba/risk-score/${user.id}`).set('Authorization', authHeader(user));

    expect(res.status).toBe(200);
    expect(res.body.priorityBoost).toBe(0);
    expect(res.body.priorityRules).toEqual([]);
  });
});
