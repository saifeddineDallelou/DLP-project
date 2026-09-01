const prisma = require('./prisma');
const { recomputeBaseline } = require('./baseline');

/**
 * Background baseline refresh.
 *
 * Until this existed, a baseline only changed when an admin clicked Recompute.
 * That makes "normal" a snapshot of whenever someone last remembered, and the
 * numbers drift out of date exactly as a person's role changes -- a developer
 * moving onto a data-heavy project keeps being scored against the baseline of
 * the job they used to do, and alerts every day until somebody notices.
 * Commercial UEBA baselines adapt continuously for this reason.
 *
 * Deliberately a plain interval rather than a cron library or a job queue:
 * one periodic task in a single-process API does not justify the dependency,
 * and an interval is honest about what it is. If this ever runs multi-instance,
 * this is the thing that needs replacing -- every instance would refresh the
 * same baselines concurrently.
 */

const DEFAULT_INTERVAL_MINUTES = 60;
const DEFAULT_STALE_HOURS = 24;
const DEFAULT_WINDOW_DAYS = 30;

/**
 * Refresh every baseline older than `staleHours`.
 *
 * Exported separately from the scheduler so tests can run one pass
 * deterministically instead of waiting on a timer.
 */
async function refreshStaleBaselines({
  staleHours = DEFAULT_STALE_HOURS,
  windowDays = DEFAULT_WINDOW_DAYS,
  logger = console,
} = {}) {
  const cutoff = new Date(Date.now() - staleHours * 60 * 60 * 1000);
  const windowStart = new Date(Date.now() - windowDays * 24 * 60 * 60 * 1000);

  const stale = await prisma.userBehaviorBaseline.findMany({
    where: { lastUpdated: { lt: cutoff } },
    select: { userId: true },
  });

  // Users the agent is reporting on who have no baseline at all yet. Without
  // this the job only ever maintains baselines that already exist, so a newly
  // monitored endpoint would sit unscored until an admin noticed and pressed
  // Recompute -- which is exactly the manual step this job exists to remove.
  const seen = await prisma.behaviorEvent.groupBy({
    by: ['userId'],
    where: { timestamp: { gte: windowStart } },
    _count: { _all: true },
  });
  const existing = new Set(
    (await prisma.userBehaviorBaseline.findMany({ select: { userId: true } }))
      .map((b) => b.userId),
  );
  const unbaselined = seen
    .map((s) => s.userId)
    .filter((id) => !existing.has(id));

  const targets = [...stale.map((s) => s.userId), ...unbaselined];
  const result = {
    checked: targets.length,
    created: 0,
    refreshed: 0,
    skipped: 0,
    failed: 0,
  };
  const isNew = new Set(unbaselined);

  for (const userId of targets) {
    try {
      const outcome = await recomputeBaseline({ userId, days: windowDays });

      if (!outcome) {
        // No events in the window. Leave the existing baseline alone rather
        // than zeroing it: a user on three weeks' leave should come back to
        // the baseline they had, not to one that says they normally do
        // nothing and now flags their first working day as anomalous.
        result.skipped += 1;
        continue;
      }

      // Audited with a null userId, which AuditLog already allows. That the
      // actor is absent is the point: it distinguishes an automatic refresh
      // from an admin reshaping a baseline by hand, and the audit trail exists
      // largely to catch the latter.
      await prisma.auditLog.create({
        data: {
          userId: null,
          action: 'RECOMPUTE_BEHAVIOR_BASELINE',
          resource: 'user_behavior_baseline',
          resourceId: outcome.baseline.id,
          metadata: {
            monitoredUserId: userId,
            source: 'SCHEDULED',
            // Distinguishes a first baseline for a newly seen user from an
            // update to an existing one -- an auditor reading the trail should
            // not have to infer which happened.
            reason: isNew.has(userId) ? 'BOOTSTRAP' : 'STALE',
            days: windowDays,
            eventCount: outcome.computedFrom.eventCount,
            avgDailyFiles: outcome.baseline.avgDailyFiles,
            avgDailyVolumeMB: outcome.baseline.avgDailyVolumeMB,
          },
        },
      });

      if (isNew.has(userId)) result.created += 1;
      else result.refreshed += 1;
    } catch (err) {
      // One bad user must not abort the pass for everyone else.
      result.failed += 1;
      logger.error(`[baseline-refresh] ${userId}: ${err.message}`);
    }
  }

  return result;
}

function startBaselineRefresh({
  intervalMinutes = Number(process.env.BASELINE_REFRESH_INTERVAL_MINUTES) || DEFAULT_INTERVAL_MINUTES,
  staleHours = Number(process.env.BASELINE_STALE_HOURS) || DEFAULT_STALE_HOURS,
  windowDays = Number(process.env.BASELINE_WINDOW_DAYS) || DEFAULT_WINDOW_DAYS,
  logger = console,
} = {}) {
  const run = async () => {
    try {
      const r = await refreshStaleBaselines({ staleHours, windowDays, logger });
      if (r.checked > 0) {
        logger.log(
          `[baseline-refresh] checked=${r.checked} created=${r.created} ` +
          `refreshed=${r.refreshed} skipped=${r.skipped} failed=${r.failed}`,
        );
      }
    } catch (err) {
      logger.error(`[baseline-refresh] pass failed: ${err.message}`);
    }
  };

  run();   // once at boot, so a restart does not wait a full interval
  const timer = setInterval(run, intervalMinutes * 60 * 1000);
  // Do not hold the process open on shutdown just for this.
  if (typeof timer.unref === 'function') timer.unref();

  logger.log(
    `[baseline-refresh] every ${intervalMinutes}m, refreshing baselines older than ${staleHours}h`,
  );

  return timer;
}

module.exports = {
  DEFAULT_INTERVAL_MINUTES,
  DEFAULT_STALE_HOURS,
  DEFAULT_WINDOW_DAYS,
  refreshStaleBaselines,
  startBaselineRefresh,
};
