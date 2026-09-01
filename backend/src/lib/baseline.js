const prisma = require('./prisma');
const { median } = require('./ueba-scoring');

/**
 * Recompute one user's behaviour baseline from their recorded event history.
 *
 * Lives here rather than inline in the route because two callers need it: the
 * admin-triggered POST /baseline/:userId/recompute, and the background refresh
 * job (see baseline-refresh.js). A second implementation would drift from the
 * first, and the whole point of the refresh job is that it produces exactly
 * what the manual button produces.
 *
 * Returns null when the user has no events in the window -- there is nothing to
 * compute a baseline from, and inventing one would be worse than having none.
 */
async function recomputeBaseline({ userId, days = 30, department }) {
  const since = new Date(Date.now() - days * 24 * 60 * 60 * 1000);

  const events = await prisma.behaviorEvent.findMany({
    where: { userId, timestamp: { gte: since } },
    select: { eventType: true, metadata: true, timestamp: true },
  });

  if (events.length === 0) return null;

  // Bucket per calendar day, so the baseline can be a median across days rather
  // than a mean. The working-hour bounds were always outlier-resistant
  // (10th/90th percentile); file count and volume were sum/days, so one 8 GB
  // afternoon shifted the number every later day was judged against.
  const perDay = new Map();
  const dayKey = (d) => new Date(d).toISOString().slice(0, 10);

  let usbInserts = 0;
  let largeFileTransfers = 0;
  const hours = [];

  for (const e of events) {
    const key = dayKey(e.timestamp);
    if (!perDay.has(key)) perDay.set(key, { files: 0, volumeMB: 0, usb: 0 });
    const day = perDay.get(key);

    if (e.eventType === 'FILE_ACCESS' || e.eventType === 'AFTER_HOURS_ACCESS') {
      day.files += Number(e.metadata?.count) || 0;
      day.volumeMB += Number(e.metadata?.sizeMB) || 0;
      if (typeof e.metadata?.hour === 'number') hours.push(e.metadata.hour);
    } else if (e.eventType === 'USB_INSERT') {
      day.usb += 1;
      usbInserts += 1;
    } else if (e.eventType === 'LARGE_FILE_TRANSFER') {
      // Its own event, on top of (not part of) FILE_ACCESS/AFTER_HOURS_ACCESS
      // -- a file over the large-file threshold is excluded from the routine
      // content-scan path entirely (see agent/src/file_watcher.py), so its
      // volume is never double-counted.
      day.volumeMB += Number(e.metadata?.sizeMB) || 0;
      largeFileTransfers += 1;
    }
  }

  // Median across ACTIVE days only -- days the user generated no events are
  // excluded rather than counted as zero. The question a baseline answers is
  // "on a day this person is working, what is typical"; padding with weekends
  // and leave drags every baseline toward zero and makes an ordinary Monday
  // look anomalous.
  const activeDays = [...perDay.values()];
  const medianFiles = median(activeDays.map((d) => d.files));
  const medianVolume = median(activeDays.map((d) => d.volumeMB));
  const medianUsb = median(activeDays.map((d) => d.usb));

  hours.sort((a, b) => a - b);
  // 10th/90th percentile rather than min/max -- a couple of one-off late nights
  // shouldn't redefine this user's whole working-hours baseline.
  const percentile = (p) => (hours.length ? hours[Math.floor(p * (hours.length - 1))] : null);
  const round2 = (n) => Math.round(n * 100) / 100;

  const existing = await prisma.userBehaviorBaseline.findUnique({ where: { userId } });
  // Only overwrite the declared department when a caller actually supplies one
  // -- a recompute is about the numbers, and silently clearing a peer group as
  // a side effect would drop the user out of peer scoring.
  const resolvedDepartment = department ?? existing?.department ?? null;

  const numbers = {
    department: resolvedDepartment,
    avgDailyFiles: round2(medianFiles),
    avgDailyVolumeMB: round2(medianVolume),
    avgWorkingHourStart: percentile(0.1) ?? existing?.avgWorkingHourStart ?? 9,
    avgWorkingHourEnd: percentile(0.9) ?? existing?.avgWorkingHourEnd ?? 18,
    avgUsbFrequency: round2(medianUsb),
    lastUpdated: new Date(),
  };

  const baseline = await prisma.userBehaviorBaseline.upsert({
    where: { userId },
    update: numbers,
    create: { userId, riskScore: 0, ...numbers },
  });

  return {
    baseline,
    computedFrom: {
      eventCount: events.length,
      days,
      activeDays: activeDays.length,
      largeFileTransfers,
      usbInserts,
      // Named so the response says plainly what statistic produced these
      // numbers -- a caller comparing two baselines needs to know one is a
      // median across active days, not a mean across the whole window.
      statistic: 'median-across-active-days',
    },
  };
}

module.exports = { recomputeBaseline };
