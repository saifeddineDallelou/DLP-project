import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, test, vi } from 'vitest';

vi.mock('../services/api.js', () => ({
  default: { get: vi.fn(), post: vi.fn(), patch: vi.fn(), delete: vi.fn() },
}));

import api from '../services/api.js';
import AiPolicy from './AiPolicy.jsx';
import { parseDetectionSample } from '../utils/format.js';

function attempt(overrides = {}) {
  return {
    id: overrides.id ?? 'att-1',
    platform: 'OPENAI_CHATGPT',
    method: 'BROWSER',
    riskScore: 0.7,
    blocked: true,
    attempts: 1,
    lastAttemptAt: null,
    reviewRequested: false,
    contentSample: 'edm:customers:row 1 record(s) matching customers on 2 field(s): city+name',
    timestamp: '2026-09-02T09:08:25Z',
    agent: { id: 'a1', hostname: 'SPIDEYPC' },
    policy: { id: 'p1', name: 'PII Detection' },
    ...overrides,
  };
}

function mockAttempts(attempts) {
  api.get.mockResolvedValue({
    data: { attempts, total: attempts.length, page: 1, limit: 50 },
  });
}

beforeEach(() => vi.clearAllMocks());

// An EDM hit says the content WAS one of the organisation's own records; a
// regex hit says it merely looked sensitive. That is the strongest signal in
// this queue and it used to render as an undifferentiated monospace string.
describe('parseDetectionSample', () => {
  test('recognises an EDM sample and names the set', () => {
    const d = parseDetectionSample('edm:customers:row 2 record(s) matching customers');
    expect(d.isEdm).toBe(true);
    expect(d.setName).toBe('customers');
  });

  test('strips the machine-readable prefix once the badge carries it', () => {
    const d = parseDetectionSample('edm:staff:city 3 value(s) matching staff.city');
    expect(d.text).toBe('3 value(s) matching staff.city');
  });

  test('finds the marker after a drag-drop filename prefix', () => {
    const d = parseDetectionSample('DRAG:cards.csv edm:customers:row 1 record(s)');
    expect(d.isEdm).toBe(true);
    expect(d.setName).toBe('customers');
  });

  test('leaves a regex sample untouched', () => {
    const d = parseDetectionSample('credit_card ****-****-****-4242');
    expect(d.isEdm).toBe(false);
    expect(d.setName).toBeNull();
    expect(d.text).toBe('credit_card ****-****-****-4242');
  });

  test('handles a missing sample without throwing', () => {
    expect(parseDetectionSample(null)).toEqual({ isEdm: false, setName: null, text: '' });
    expect(parseDetectionSample(undefined).isEdm).toBe(false);
  });

  test('never returns an empty label for a bare marker', () => {
    // Stripping the prefix must not leave a blank cell.
    const d = parseDetectionSample('edm:customers:row');
    expect(d.text.length).toBeGreaterThan(0);
  });
});

describe('AiPolicy page', () => {
  test('lists attempts with platform, agent and policy', async () => {
    mockAttempts([attempt()]);
    render(<AiPolicy />);

    expect(await screen.findByText('ChatGPT')).toBeInTheDocument();
    expect(screen.getByText('SPIDEYPC')).toBeInTheDocument();
    expect(screen.getByText('PII Detection')).toBeInTheDocument();
  });

  test('marks an EDM detection as EDM', async () => {
    mockAttempts([attempt()]);
    render(<AiPolicy />);
    expect(await screen.findByText('EDM')).toBeInTheDocument();
  });

  test('does not mark a regex detection as EDM', async () => {
    mockAttempts([attempt({ contentSample: 'credit_card ****-****-****-4242' })]);
    render(<AiPolicy />);

    expect(await screen.findByText('ChatGPT')).toBeInTheDocument();
    expect(screen.queryByText('EDM')).not.toBeInTheDocument();
  });

  test('shows a repeat count when one row represents several attempts', async () => {
    // Eight blocked copies as one row reading x8, not eight rows -- and not
    // one row reading "1", which is how a per-window throttle used to
    // report a persistent attempt.
    mockAttempts([attempt({ attempts: 8, lastAttemptAt: '2026-09-02T09:08:42Z' })]);
    render(<AiPolicy />);
    expect(await screen.findByText('×8')).toBeInTheDocument();
  });

  test('a single attempt shows no repeat chip', async () => {
    mockAttempts([attempt({ attempts: 1 })]);
    render(<AiPolicy />);

    expect(await screen.findByText('ChatGPT')).toBeInTheDocument();
    expect(screen.queryByText(/^×/)).not.toBeInTheDocument();
  });

  test('distinguishes blocked from allowed', async () => {
    // 'Blocked' and 'Allowed' also label the stat cards and a column header,
    // so this has to look inside the table body specifically.
    mockAttempts([attempt({ id: 'a', blocked: true }), attempt({ id: 'b', blocked: false })]);
    const { container } = render(<AiPolicy />);
    // Both rows carry the same hostname, so wait on the count settling
    // rather than on a value that is deliberately duplicated.
    await waitFor(() =>
      expect(container.querySelectorAll('tbody tr')).toHaveLength(2));

    const rows = [...container.querySelectorAll('tbody tr')];
    expect(rows).toHaveLength(2);
    expect(rows[0].textContent).toContain('Blocked');
    expect(rows[1].textContent).toContain('Allowed');
  });

  test('shows an empty state when nothing has been attempted', async () => {
    mockAttempts([]);
    render(<AiPolicy />);
    expect(await screen.findByText(/no ai leak attempts detected/i)).toBeInTheDocument();
  });

  test('opening a row shows the attempt count in the detail panel', async () => {
    const user = userEvent.setup();
    mockAttempts([attempt({ attempts: 5, lastAttemptAt: '2026-09-02T09:08:42Z' })]);
    const renderResult = render(<AiPolicy />);

    const { container } = renderResult;
    await screen.findByText('SPIDEYPC');
    await user.click(container.querySelector('tbody tr'));
    await waitFor(() => expect(screen.getByText('Attempts')).toBeInTheDocument());
    expect(screen.getByText(/^5 \(last/)).toBeInTheDocument();
  });
});
