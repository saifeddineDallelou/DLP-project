import { describe, expect, test, vi, afterEach } from 'vitest';
import {
  formatDate,
  timeAgo,
  truncate,
  titleCase,
  riskLevelFor,
  SEVERITY_TONES,
  STATUS_TONES,
  ACTION_TONES,
  AGENT_STATUS_TONES,
  RISK_LEVEL_TONES,
  EVENT_TYPE_LABELS,
  PLATFORM_LABELS,
  MONITORED_CHANNELS,
  CHANNEL_ICON,
} from './format.js';

afterEach(() => vi.useRealTimers());

describe('formatDate', () => {
  test('renders a timestamp', () => {
    expect(formatDate('2026-01-15T14:30:00Z')).toMatch(/Jan 15, 2026/);
  });

  test('shows a dash rather than "Invalid Date" for a missing value', () => {
    // Half these fields are nullable in the schema -- resolvedAt, lastSeen,
    // adminNote. A table full of "Invalid Date" is worse than a table of
    // dashes.
    expect(formatDate(null)).toBe('—');
    expect(formatDate(undefined)).toBe('—');
    expect(formatDate('')).toBe('—');
  });
});

describe('timeAgo', () => {
  const now = new Date('2026-01-15T12:00:00Z');
  const ago = (ms) => {
    vi.useFakeTimers();
    vi.setSystemTime(now);
    return timeAgo(new Date(now.getTime() - ms).toISOString());
  };

  test('says "Just now" under a minute', () => {
    expect(ago(30 * 1000)).toBe('Just now');
  });

  test('counts minutes, then hours, then days', () => {
    expect(ago(5 * 60 * 1000)).toBe('5m ago');
    expect(ago(3 * 60 * 60 * 1000)).toBe('3h ago');
    expect(ago(2 * 24 * 60 * 60 * 1000)).toBe('2d ago');
  });

  test('rolls over at the boundaries rather than showing "60m"', () => {
    expect(ago(60 * 60 * 1000)).toBe('1h ago');
    expect(ago(24 * 60 * 60 * 1000)).toBe('1d ago');
  });

  test('distinguishes "never seen" from "seen just now"', () => {
    // An agent that has never checked in is a different operational state
    // from one that checked in seconds ago, and the fleet view has to show
    // which.
    expect(timeAgo(null)).toBe('Never');
  });
});

describe('truncate', () => {
  test('leaves a short string alone', () => {
    expect(truncate('abc', 8)).toBe('abc');
  });

  test('marks a shortened string with an ellipsis', () => {
    expect(truncate('abcdefghijkl', 8)).toBe('abcdefgh…');
  });

  test('returns a dash for nothing', () => {
    expect(truncate(null)).toBe('—');
  });
});

describe('titleCase', () => {
  test('turns a backend enum into something readable', () => {
    expect(titleCase('IN_PROGRESS')).toBe('In Progress');
    expect(titleCase('FALSE_POSITIVE')).toBe('False Positive');
  });

  test('handles a single word', () => {
    expect(titleCase('OPEN')).toBe('Open');
  });

  test('does not throw on empty input', () => {
    expect(titleCase('')).toBe('');
    expect(titleCase(null)).toBe('');
  });
});

describe('riskLevelFor', () => {
  test('uses the same thresholds as the backend scorer', () => {
    // These must match ueba-scoring.js riskLevel(). If they drift, the badge
    // on a card contradicts the level the API computed for the same score.
    expect(riskLevelFor(0.0)).toBe('LOW');
    expect(riskLevelFor(0.39)).toBe('LOW');
    expect(riskLevelFor(0.4)).toBe('MEDIUM');
    expect(riskLevelFor(0.69)).toBe('MEDIUM');
    expect(riskLevelFor(0.7)).toBe('HIGH');
    expect(riskLevelFor(1.0)).toBe('HIGH');
  });

  test('treats a missing score as lowest risk, not as a crash', () => {
    expect(riskLevelFor(null)).toBe('LOW');
    expect(riskLevelFor(undefined)).toBe('LOW');
  });
});

describe('tone maps cover every backend enum value', () => {
  // A missing key renders an unstyled badge -- invisible text on some
  // backgrounds. These lists mirror schema.prisma; adding a value there
  // without adding it here is the failure this catches.
  test.each([
    ['Severity', SEVERITY_TONES, ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']],
    ['IncidentStatus', STATUS_TONES, ['OPEN', 'IN_PROGRESS', 'RESOLVED', 'FALSE_POSITIVE']],
    ['Action', ACTION_TONES, ['ALLOW', 'ALERT', 'BLOCK', 'QUARANTINE']],
    ['AgentStatus', AGENT_STATUS_TONES, ['ACTIVE', 'INACTIVE', 'ERROR']],
    ['risk level', RISK_LEVEL_TONES, ['LOW', 'MEDIUM', 'HIGH']],
  ])('%s', (_name, map, values) => {
    for (const v of values) {
      expect(map[v], `missing tone for ${v}`).toBeDefined();
    }
  });

  test('every BehaviorEventType has a human label', () => {
    for (const t of [
      'FILE_ACCESS', 'USB_INSERT', 'CLIPBOARD_COPY',
      'SCREENSHOT', 'APP_LAUNCH', 'AFTER_HOURS_ACCESS', 'LARGE_FILE_TRANSFER',
    ]) {
      expect(EVENT_TYPE_LABELS[t], `missing label for ${t}`).toBeDefined();
    }
  });

  test('every AiPlatform has a human label', () => {
    for (const p of [
      'OPENAI_CHATGPT', 'ANTHROPIC_CLAUDE', 'GOOGLE_GEMINI', 'MICROSOFT_COPILOT',
      'PERPLEXITY', 'POE', 'CHARACTER_AI', 'MISTRAL', 'GROK', 'META_AI',
      'DEEPSEEK', 'HUGGINGFACE', 'YOU_COM', 'PI_AI', 'GROQ', 'COHERE', 'OTHER_AI',
    ]) {
      expect(PLATFORM_LABELS[p], `missing label for ${p}`).toBeDefined();
    }
  });
});


describe('MONITORED_CHANNELS', () => {
  test('includes every channel a monitor actually reports on', () => {
    // FILE_UPLOAD was missing from the Reports page's own copy of this list,
    // so in-page upload blocks -- a channel with real incidents -- were left
    // out of the breakdown entirely.
    for (const ch of ['FILE', 'FILE_UPLOAD', 'CLIPBOARD', 'SCREENSHOT', 'USB', 'PRINT']) {
      expect(MONITORED_CHANNELS).toContain(ch);
    }
  });

  test('leaves out a channel nothing produces', () => {
    // NETWORK is a value the enum accepts and no monitor emits. Charting it
    // draws a row of zeroes that reads as "nothing happened here" rather than
    // "nothing watches this".
    expect(MONITORED_CHANNELS).not.toContain('NETWORK');
  });

  test('every monitored channel has an icon', () => {
    // The table falls back to a generic file icon, so a missing entry made a
    // blocked upload indistinguishable from a file found at rest.
    for (const ch of MONITORED_CHANNELS) {
      expect(CHANNEL_ICON[ch]).toBeTruthy();
    }
  });
});
