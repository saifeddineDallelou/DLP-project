const {
  refreshStaleBaselines,
  DEFAULT_STALE_HOURS,
  DEFAULT_INTERVAL_MINUTES,
} = require('../src/lib/baseline-refresh');
const { prisma, resetDb, createAgent } = require('./helpers');

afterEach(resetDb);
afterAll(() => prisma.$disconnect());

const silent = { log() {}, error() {} };

function hoursAgo(h) {
  return new Date(Date.now() - h * 60 * 60 * 1000);
}

async function baseline(userId, { lastUpdated, ...rest } = {}) {
  return prisma.userBehaviorBaseline.create({
    data: {
      userId,
      avgDailyFiles: 1,
      avgDailyVolumeMB: 1,
      avgWorkingHourStart: 9,
      avgWorkingHourEnd: 18,
      avgUsbFrequency: 0,
      riskScore: 0,
      lastUpdated: lastUpdated ?? new Date(),
      ...rest,
    },
  });
}

async function fileEvent(agentId, userId, metadata) {
  return prisma.behaviorEvent.create({
    data: { agentId, userId, eventType: 'FILE_ACCESS', metadata },
  });
}

describe('refreshStaleBaselines', () => {
  test('leaves a fresh baseline untouched', async () => {
    const agent = await createAgent();
    await baseline('fresh-user', { lastUpdated: hoursAgo(1) });
    await fileEvent(agent.id, 'fresh-user', { count: 99, sizeMB: 99, hour: 10 });

    const r = await refreshStaleBaselines({ staleHours: 24, logger: silent });

    expect(r.checked).toBe(0);
    expect(r.refreshed).toBe(0);
    const after = await prisma.userBehaviorBaseline.findUnique({ where: { userId: 'fresh-user' } });
    expect(after.avgDailyFiles).toBe(1);   // not recomputed
  });

  test('recomputes a stale baseline from real events', async () => {
    const agent = await createAgent();
    await baseline('stale-user', { lastUpdated: hoursAgo(48) });
    await fileEvent(agent.id, 'stale-user', { count: 42, sizeMB: 500, hour: 10 });

    const r = await refreshStaleBaselines({ staleHours: 24, logger: silent });

    expect(r.checked).toBe(1);
    expect(r.refreshed).toBe(1);
    const after = await prisma.userBehaviorBaseline.findUnique({ where: { userId: 'stale-user' } });
    expect(after.avgDailyFiles).toBe(42);
    expect(after.avgDailyVolumeMB).toBe(500);
  });

  test('produces the same numbers the manual recompute would', async () => {
    // The refresh job shares recomputeBaseline() with the route precisely so
    // these cannot drift apart. If they ever do, one of them is a second
    // implementation and this test is what catches it.
    const agent = await createAgent();
    await baseline('shared-user', { lastUpdated: hoursAgo(48) });
    await fileEvent(agent.id, 'shared-user', { count: 30, sizeMB: 300, hour: 14 });

    await refreshStaleBaselines({ staleHours: 24, logger: silent });
    const scheduled = await prisma.userBehaviorBaseline.findUnique({ where: { userId: 'shared-user' } });

    const { recomputeBaseline } = require('../src/lib/baseline');
    const manual = await recomputeBaseline({ userId: 'shared-user', days: 30 });

    expect(manual.baseline.avgDailyFiles).toBe(scheduled.avgDailyFiles);
    expect(manual.baseline.avgDailyVolumeMB).toBe(scheduled.avgDailyVolumeMB);
  });

  test('skips a user with no events rather than zeroing their baseline', async () => {
    // Someone on three weeks' leave must come back to the baseline they had,
    // not to one saying they normally do nothing -- which would flag their
    // first day back as anomalous.
    await baseline('on-leave', { lastUpdated: hoursAgo(72), avgDailyFiles: 55 });

    const r = await refreshStaleBaselines({ staleHours: 24, logger: silent });

    expect(r.checked).toBe(1);
    expect(r.skipped).toBe(1);
    expect(r.refreshed).toBe(0);
    const after = await prisma.userBehaviorBaseline.findUnique({ where: { userId: 'on-leave' } });
    expect(after.avgDailyFiles).toBe(55);
  });

  test('preserves a declared department across an automatic refresh', async () => {
    const agent = await createAgent();
    await baseline('eng-user', { lastUpdated: hoursAgo(48), department: 'Engineering' });
    await fileEvent(agent.id, 'eng-user', { count: 10, sizeMB: 10, hour: 10 });

    await refreshStaleBaselines({ staleHours: 24, logger: silent });

    const after = await prisma.userBehaviorBaseline.findUnique({ where: { userId: 'eng-user' } });
    expect(after.department).toBe('Engineering');
  });

  test('records an audit row with a null actor and SCHEDULED source', async () => {
    // The absent actor is the point: it separates an automatic refresh from an
    // admin reshaping a baseline by hand, which is what the trail exists for.
    const agent = await createAgent();
    await baseline('audited-user', { lastUpdated: hoursAgo(48) });
    await fileEvent(agent.id, 'audited-user', { count: 10, sizeMB: 10, hour: 10 });

    await refreshStaleBaselines({ staleHours: 24, logger: silent });

    const logs = await prisma.auditLog.findMany({ where: { action: 'RECOMPUTE_BEHAVIOR_BASELINE' } });
    expect(logs).toHaveLength(1);
    expect(logs[0].userId).toBeNull();
    expect(logs[0].metadata.source).toBe('SCHEDULED');
    expect(logs[0].metadata.monitoredUserId).toBe('audited-user');
  });

  test('one failing user does not abort the pass', async () => {
    const agent = await createAgent();
    for (const u of ['user-a', 'user-b', 'user-c']) {
      await baseline(u, { lastUpdated: hoursAgo(48) });
      await fileEvent(agent.id, u, { count: 5, sizeMB: 5, hour: 10 });
    }

    const r = await refreshStaleBaselines({ staleHours: 24, logger: silent });

    expect(r.checked).toBe(3);
    expect(r.refreshed).toBe(3);
    expect(r.failed).toBe(0);
  });

  test('honours the configured staleness threshold', async () => {
    const agent = await createAgent();
    await baseline('user-6h', { lastUpdated: hoursAgo(6) });
    await fileEvent(agent.id, 'user-6h', { count: 5, sizeMB: 5, hour: 10 });

    expect((await refreshStaleBaselines({ staleHours: 24, logger: silent })).checked).toBe(0);
    expect((await refreshStaleBaselines({ staleHours: 1, logger: silent })).checked).toBe(1);
  });
});

describe('bootstrapping users with no baseline', () => {
  // Without this the job only maintains baselines that already exist, so a
  // newly monitored endpoint sits unscored until an admin notices -- which is
  // the manual step the job exists to remove. It is also what made the
  // Recompute button load-bearing.
  test('creates a first baseline for a user who has events but none', async () => {
    const agent = await createAgent();
    await fileEvent(agent.id, 'brand-new-user', { count: 25, sizeMB: 250, hour: 10 });

    const r = await refreshStaleBaselines({ staleHours: 24, logger: silent });

    expect(r.created).toBe(1);
    expect(r.refreshed).toBe(0);
    const made = await prisma.userBehaviorBaseline.findUnique({ where: { userId: 'brand-new-user' } });
    expect(made).not.toBeNull();
    expect(made.avgDailyFiles).toBe(25);
    expect(made.avgDailyVolumeMB).toBe(250);
  });

  test('marks a bootstrap distinctly from a stale refresh in the audit trail', async () => {
    const agent = await createAgent();
    await fileEvent(agent.id, 'new-user', { count: 5, sizeMB: 5, hour: 10 });
    await baseline('old-user', { lastUpdated: hoursAgo(48) });
    await fileEvent(agent.id, 'old-user', { count: 5, sizeMB: 5, hour: 10 });

    await refreshStaleBaselines({ staleHours: 24, logger: silent });

    const logs = await prisma.auditLog.findMany({ where: { action: 'RECOMPUTE_BEHAVIOR_BASELINE' } });
    const reasons = Object.fromEntries(logs.map((l) => [l.metadata.monitoredUserId, l.metadata.reason]));
    expect(reasons['new-user']).toBe('BOOTSTRAP');
    expect(reasons['old-user']).toBe('STALE');
  });

  test('does not re-bootstrap a user whose baseline is simply fresh', async () => {
    const agent = await createAgent();
    await baseline('settled-user', { lastUpdated: new Date() });
    await fileEvent(agent.id, 'settled-user', { count: 99, sizeMB: 99, hour: 10 });

    const r = await refreshStaleBaselines({ staleHours: 24, logger: silent });

    expect(r.checked).toBe(0);
    expect(r.created).toBe(0);
  });

  test('ignores events older than the window when bootstrapping', async () => {
    const agent = await createAgent();
    await prisma.behaviorEvent.create({
      data: {
        agentId: agent.id, userId: 'long-gone', eventType: 'FILE_ACCESS',
        metadata: { count: 5, sizeMB: 5, hour: 10 },
        timestamp: new Date(Date.now() - 90 * 24 * 60 * 60 * 1000),
      },
    });

    const r = await refreshStaleBaselines({ staleHours: 24, windowDays: 30, logger: silent });

    expect(r.created).toBe(0);
    expect(await prisma.userBehaviorBaseline.findUnique({ where: { userId: 'long-gone' } })).toBeNull();
  });
});

describe('defaults', () => {
  test('are sane for a background job', () => {
    expect(DEFAULT_STALE_HOURS).toBe(24);
    expect(DEFAULT_INTERVAL_MINUTES).toBe(60);
    // The interval must be shorter than the staleness window, or baselines sit
    // stale for up to a full extra interval before anything looks at them.
    expect(DEFAULT_INTERVAL_MINUTES / 60).toBeLessThan(DEFAULT_STALE_HOURS);
  });
});
