/**
 * UEBA deviation scoring.
 *
 * Kept out of routes/ueba.js because this is the only genuinely algorithmic
 * part of the module -- it needs unit tests that do not go near HTTP or the
 * database, and the route needs to stay readable as a route.
 *
 * WHAT CHANGED AND WHY
 * Until this module existed, the live risk score was:
 *
 *     baseline.riskScore + afterHours*0.1 + usbInserts*0.05 + largeFiles*0.15
 *
 * -- a stored scalar plus a count of event *types*. It never read
 * avgDailyFiles, avgDailyVolumeMB or the working-hour bounds, so the baseline
 * that POST /baseline/:userId/recompute works to compute was displayed on the
 * dashboard and then ignored by the thing it exists to feed. Three USB inserts
 * scored identically whether the user moved 3 KB or 300 GB.
 *
 * This scores DEVIATION: how far today sits from what is normal for this
 * person, and -- where a department is declared -- from what is normal for
 * their peers.
 */

// How many times normal counts as fully anomalous. At 5, a user doing 5x their
// usual volume maxes that metric's contribution; 2x contributes a quarter.
// Raising it means fewer alerts. Deliberately a named constant: it is the one
// number an operator would realistically want to tune.
const FULL_SIGNAL_RATIO = 5;

// A baseline of 0 is meaningful ("this person never does this"), not missing --
// recompute writes a real 0 when it observed none. But scoring the very first
// USB insert of a new starter as maximally anomalous is a false positive
// generator, so a zero baseline needs an absolute floor before it fires.
const ZERO_BASELINE_FLOORS = {
  files: 20,
  volumeMB: 100,
  usb: 1,
};

// A zero baseline is capped below full signal. "Has not done this during the
// baseline window" is weaker evidence than "does this constantly and today did
// 30x more" -- the first is an absence of observations, the second is a
// measured ratio. Without this cap, combined with the dominant-signal floor
// below, a new starter's first USB insert alone would score HIGH. Novel
// behaviour should raise the score, not decide it.
const ZERO_BASELINE_MAX_SIGNAL = 0.6;

// What a single fully anomalous metric scores on its own, before any other
// signal is considered. At 0.75 it clears the HIGH band (0.7) unaided, so one
// metric at full deviation raises the alarm by itself. Lowering it toward 0
// reverts to a pure weighted mean, which requires several metrics to be
// abnormal at once -- see the reasoning in combine().
const DOMINANT_SIGNAL_FACTOR = 0.75;

const WEIGHTS = {
  volume: 0.35,   // volume moved is the signal exfiltration shows up in first
  files:  0.25,
  hours:  0.20,
  usb:    0.20,
};

/**
 * Convert an observed value and a baseline into a 0..1 anomaly signal.
 *
 * Linear between 1x and FULL_SIGNAL_RATIO x rather than logarithmic: an
 * analyst has to be able to read "28x normal" off the dashboard and see why
 * the number is what it is. A log curve scores large ratios more gracefully
 * but makes the contribution impossible to explain at a glance.
 */
function deviationSignal(actual, baseline, floor) {
  const a = Number(actual) || 0;
  const b = Number(baseline) || 0;

  if (a <= 0) return { signal: 0, ratio: 0 };

  if (b <= 0) {
    // No established normal to divide by. Fire only once the raw value clears
    // an absolute floor, scaling in below it.
    const f = floor > 0 ? floor : 1;
    return { signal: Math.min(ZERO_BASELINE_MAX_SIGNAL, (a / f) * ZERO_BASELINE_MAX_SIGNAL), ratio: null };
  }

  const ratio = a / b;
  if (ratio <= 1) return { signal: 0, ratio };

  const signal = Math.min(1, (ratio - 1) / (FULL_SIGNAL_RATIO - 1));
  return { signal, ratio };
}

/**
 * Fraction of today's activity that fell outside the user's normal working
 * window. Handles a window that wraps midnight (e.g. a 22-06 night shift),
 * which a naive start<=h<=end comparison scores exactly backwards.
 */
function hoursSignal(activeHours, start, end) {
  const hours = (activeHours || []).filter((h) => typeof h === 'number');
  if (hours.length === 0) return { signal: 0, outside: 0, total: 0 };

  const s = Number(start);
  const e = Number(end);
  if (!Number.isFinite(s) || !Number.isFinite(e)) {
    return { signal: 0, outside: 0, total: hours.length };
  }

  const inWindow = (h) => (s <= e ? h >= s && h <= e : h >= s || h <= e);
  const outside = hours.filter((h) => !inWindow(h)).length;

  return { signal: outside / hours.length, outside, total: hours.length };
}

/** Median of a numeric array. Returns 0 for an empty array. */
function median(values) {
  const nums = (values || []).filter((n) => typeof n === 'number' && Number.isFinite(n));
  if (nums.length === 0) return 0;
  const sorted = [...nums].sort((a, b) => a - b);
  const mid = Math.floor(sorted.length / 2);
  return sorted.length % 2 === 0 ? (sorted[mid - 1] + sorted[mid]) / 2 : sorted[mid];
}

/**
 * Combine per-metric signals into one 0..1 score.
 *
 * Where a peer baseline is available, each metric takes max(self, peer). Max
 * rather than a blend because the case peer comparison exists to catch is a
 * SELF baseline that has been poisoned -- either by a deliberately narrow
 * recompute window, or by the user's bad behaviour having been present
 * throughout the window it was computed from. Blending lets exactly the
 * corrupted half drag the result back down.
 */
function combine(components) {
  let weighted = 0;
  let weightUsed = 0;
  let strongest = 0;

  for (const [key, weight] of Object.entries(WEIGHTS)) {
    const c = components[key];
    if (!c) continue;
    const signal = c.peerSignal != null ? Math.max(c.signal, c.peerSignal) : c.signal;
    weighted += signal * weight;
    weightUsed += weight;
    if (signal > strongest) strongest = signal;
  }

  if (weightUsed === 0) return 0;

  // Renormalise so a MISSING metric does not silently deflate the score --
  // three strong signals out of four should read as high risk, not as 75% of
  // high risk.
  const mean = weighted / weightUsed;

  // ...but renormalising does not help a metric that is present and merely
  // normal, and a plain weighted mean therefore demands BREADTH of anomaly:
  // with volume and files together carrying 0.60, a user moving 80x their
  // usual volume and touching 25x their usual files could not reach HIGH,
  // because their working hours and USB use were unremarkable.
  //
  // That is the wrong shape for this problem. Exfiltration is characteristically
  // narrow and deep -- one metric wildly abnormal, the rest ordinary -- so a
  // single fully anomalous metric has to be sufficient on its own. The floor
  // below is what lets it be, while still letting several moderate signals
  // accumulate through the mean.
  return Math.max(mean, strongest * DOMINANT_SIGNAL_FACTOR);
}

function riskLevel(score) {
  return score >= 0.7 ? 'HIGH' : score >= 0.4 ? 'MEDIUM' : 'LOW';
}

module.exports = {
  FULL_SIGNAL_RATIO,
  DOMINANT_SIGNAL_FACTOR,
  ZERO_BASELINE_FLOORS,
  ZERO_BASELINE_MAX_SIGNAL,
  WEIGHTS,
  deviationSignal,
  hoursSignal,
  median,
  combine,
  riskLevel,
};
