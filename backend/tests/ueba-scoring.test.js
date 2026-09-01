const {
  FULL_SIGNAL_RATIO,
  DOMINANT_SIGNAL_FACTOR,
  ZERO_BASELINE_MAX_SIGNAL,
  WEIGHTS,
  deviationSignal,
  hoursSignal,
  median,
  combine,
  riskLevel,
} = require('../src/lib/ueba-scoring');

// Pure functions -- no database, no HTTP. These are the arithmetic the whole
// UEBA score rests on, so they are worth pinning down directly rather than
// inferring from endpoint responses.

describe('deviationSignal', () => {
  test('is silent at or below baseline', () => {
    expect(deviationSignal(50, 100, 10).signal).toBe(0);
    expect(deviationSignal(100, 100, 10).signal).toBe(0);
  });

  test('scales linearly between 1x and the full-signal ratio', () => {
    // Halfway between 1x and 5x is 3x, which should give half signal.
    const mid = deviationSignal(300, 100, 10);
    expect(mid.ratio).toBeCloseTo(3, 5);
    expect(mid.signal).toBeCloseTo(0.5, 5);
  });

  test('saturates at the full-signal ratio and does not exceed 1', () => {
    expect(deviationSignal(500, 100, 10).signal).toBe(1);
    expect(deviationSignal(50000, 100, 10).signal).toBe(1);
  });

  test('reports the raw ratio so the dashboard can explain the score', () => {
    expect(deviationSignal(2800, 100, 10).ratio).toBeCloseTo(28, 5);
  });

  test('an absent observation is never anomalous', () => {
    expect(deviationSignal(0, 100, 10).signal).toBe(0);
  });

  describe('with a zero baseline', () => {
    // A recomputed baseline of 0 means "observed, never happened" -- not
    // "unknown". But firing maximum risk on a new starter's first USB insert
    // manufactures false positives, so a floor gates it.
    test('scales in below the floor rather than firing immediately', () => {
      // Half the floor gives half of the zero-baseline cap.
      expect(deviationSignal(50, 0, 100).signal).toBeCloseTo(0.3, 5);
    });

    test('caps below full signal once the floor is cleared', () => {
      // Never above the cap: an absence of observations is weaker evidence
      // than a measured ratio, and must not be able to decide the score alone.
      expect(deviationSignal(100, 0, 100).signal).toBeCloseTo(0.6, 5);
      expect(deviationSignal(400, 0, 100).signal).toBeCloseTo(0.6, 5);
      expect(deviationSignal(99999, 0, 100).signal).toBeLessThan(1);
    });

    test('cannot on its own reach the HIGH band', () => {
      // A new starter's first USB insert must not be a HIGH finding by itself.
      const soleSignal = deviationSignal(5, 0, 1).signal;
      expect(riskLevel(combine({ usb: { signal: soleSignal } }))).not.toBe('HIGH');
    });

    test('reports a null ratio, since dividing by zero explains nothing', () => {
      expect(deviationSignal(150, 0, 100).ratio).toBeNull();
    });
  });
});

describe('hoursSignal', () => {
  test('is silent when all activity is inside the window', () => {
    expect(hoursSignal([9, 12, 16], 9, 17).signal).toBe(0);
  });

  test('reports the fraction of activity outside the window', () => {
    const r = hoursSignal([9, 12, 2, 3], 9, 17);
    expect(r.outside).toBe(2);
    expect(r.total).toBe(4);
    expect(r.signal).toBeCloseTo(0.5, 5);
  });

  test('handles a window that wraps midnight', () => {
    // A 22:00-06:00 night shift. 23h and 2h are INSIDE it; 12h is not.
    // A naive start <= h <= end comparison scores this exactly backwards.
    const r = hoursSignal([23, 2, 12], 22, 6);
    expect(r.outside).toBe(1);
    expect(r.signal).toBeCloseTo(1 / 3, 5);
  });

  test('is silent with no recorded hours rather than guessing', () => {
    expect(hoursSignal([], 9, 17).signal).toBe(0);
    expect(hoursSignal(undefined, 9, 17).signal).toBe(0);
  });

  test('is silent when the window itself is unusable', () => {
    expect(hoursSignal([3], null, undefined).signal).toBe(0);
  });
});

describe('median', () => {
  test('takes the middle value of an odd-length set', () => {
    expect(median([5, 1, 3])).toBe(3);
  });

  test('averages the middle pair of an even-length set', () => {
    expect(median([1, 2, 3, 4])).toBe(2.5);
  });

  test('ignores a single extreme value where a mean would not', () => {
    const days = [10, 12, 11, 9, 8000];
    expect(median(days)).toBe(11);
    // The mean of the same days is over 1600 -- one 8 GB afternoon would have
    // redefined every subsequent day's notion of normal.
    const mean = days.reduce((a, b) => a + b, 0) / days.length;
    expect(mean).toBeGreaterThan(1600);
  });

  test('returns 0 for an empty set', () => {
    expect(median([])).toBe(0);
    expect(median(undefined)).toBe(0);
  });
});

describe('combine', () => {
  test('weights each component as declared', () => {
    const score = combine({ volume: { signal: 1 } });
    // Only one component present, so renormalisation makes it the whole score.
    expect(score).toBeCloseTo(1, 5);
  });

  test('renormalises so a missing metric does not deflate the score', () => {
    // Three maxed components out of four should read as maximum risk, not 80%.
    const score = combine({
      volume: { signal: 1 },
      files:  { signal: 1 },
      usb:    { signal: 1 },
    });
    expect(score).toBeCloseTo(1, 5);
  });

  test('mixes partial signals in proportion to their weights', () => {
    // Both signals moderate, so neither triggers the dominant-signal floor and
    // the weighted mean decides.
    const score = combine({
      volume: { signal: 0.4 },   // 0.35
      files:  { signal: 0.2 },   // 0.25
    });
    const mean = (0.4 * 0.35 + 0.2 * 0.25) / (0.35 + 0.25);
    expect(score).toBeCloseTo(mean, 5);
    expect(score).toBeGreaterThan(0.4 * DOMINANT_SIGNAL_FACTOR); // mean wins here
  });

  test('a single fully anomalous metric alone reaches the HIGH band', () => {
    // Exfiltration is narrow and deep: one metric wildly abnormal, the rest
    // ordinary. A plain weighted mean would score this MEDIUM at best, because
    // volume carries only 0.35 of the total weight.
    const score = combine({
      volume: { signal: 1 },
      files:  { signal: 0 },
      hours:  { signal: 0 },
      usb:    { signal: 0 },
    });
    expect(score).toBeCloseTo(DOMINANT_SIGNAL_FACTOR, 5);
    expect(riskLevel(score)).toBe('HIGH');
  });

  test('breadth of anomaly still scores above a single metric', () => {
    const narrow = combine({
      volume: { signal: 1 }, files: { signal: 0 }, hours: { signal: 0 }, usb: { signal: 0 },
    });
    const broad = combine({
      volume: { signal: 1 }, files: { signal: 1 }, hours: { signal: 1 }, usb: { signal: 1 },
    });
    expect(broad).toBeGreaterThan(narrow);
  });

  test('takes the peer signal when it is the stronger of the two', () => {
    // The poisoned-baseline case: the user's own baseline was inflated, so
    // self-deviation is silent, but they are still far above their peers.
    const score = combine({ volume: { signal: 0, peerSignal: 1 } });
    expect(score).toBeCloseTo(1, 5);
  });

  test('keeps the self signal when it is the stronger of the two', () => {
    const score = combine({ volume: { signal: 1, peerSignal: 0 } });
    expect(score).toBeCloseTo(1, 5);
  });

  test('is zero when nothing is measurable', () => {
    expect(combine({})).toBe(0);
  });
});

describe('riskLevel', () => {
  test('maps scores to bands', () => {
    expect(riskLevel(0.0)).toBe('LOW');
    expect(riskLevel(0.39)).toBe('LOW');
    expect(riskLevel(0.4)).toBe('MEDIUM');
    expect(riskLevel(0.69)).toBe('MEDIUM');
    expect(riskLevel(0.7)).toBe('HIGH');
    expect(riskLevel(1.0)).toBe('HIGH');
  });
});

describe('declared constants', () => {
  test('weights sum to 1, so a fully anomalous user scores exactly 1', () => {
    const total = Object.values(WEIGHTS).reduce((a, b) => a + b, 0);
    expect(total).toBeCloseTo(1, 5);
  });

  test('the full-signal ratio is the documented tuning knob', () => {
    expect(FULL_SIGNAL_RATIO).toBe(5);
  });

  test('one dominant signal clears HIGH, a capped zero-baseline one does not', () => {
    expect(riskLevel(DOMINANT_SIGNAL_FACTOR)).toBe('HIGH');
    expect(riskLevel(ZERO_BASELINE_MAX_SIGNAL * DOMINANT_SIGNAL_FACTOR)).not.toBe('HIGH');
  });
});
