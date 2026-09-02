import { render, screen, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, test, vi } from 'vitest';

vi.mock('../services/api.js', () => ({
  default: { get: vi.fn(), post: vi.fn(), patch: vi.fn(), delete: vi.fn() },
}));

import api from '../services/api.js';
import UEBA from './UEBA.jsx';

function event(userId = 'alice', overrides = {}) {
  return {
    id: `ev-${Math.random()}`,
    userId,
    eventType: 'FILE_ACCESS',
    metadata: { count: 3, sizeMB: 10, hour: 10 },
    timestamp: '2026-09-02T10:00:00Z',
    agent: { id: 'a1', hostname: 'SPIDEYPC' },
    ...overrides,
  };
}

/** An ESTABLISHED user: baseline is trusted, deviations are scored. */
function scored(userId, overrides = {}) {
  return {
    userId,
    department: null,
    baselineRiskScore: 0,
    liveRiskScore: 0.1,
    riskLevel: 'LOW',
    scoredOn: 'behaviour+policy',
    learning: null,
    deviationScore: 0.1,
    eventBonus: 0,
    priorityBoost: 0,
    priorityRules: [],
    prioritySeverities: {},
    components: {
      volume: { observed: 10, baseline: 100, ratio: 0.1, signal: 0, peerSignal: null },
      files:  { observed: 3,  baseline: 10,  ratio: 0.3, signal: 0, peerSignal: null },
      hours:  { observed: 0,  total: 3, baseline: '9-17', ratio: null, signal: 0, peerSignal: null },
      usb:    { observed: 0,  baseline: 1,   ratio: 0,   signal: 0, peerSignal: null },
    },
    peerGroup: null,
    last24h: { total: 3, afterHoursAccess: 0, usbInserts: 0, largeFileTransfers: 0 },
    baseline: {
      avgDailyFiles: 10, avgDailyVolumeMB: 100,
      avgWorkingHourStart: 9, avgWorkingHourEnd: 17,
      avgUsbFrequency: 1, activeDaysObserved: 30,
      lastUpdated: '2026-09-02T08:00:00Z',
    },
    ...overrides,
  };
}

/** A user still inside the learning period. */
function learning(userId, activeDaysObserved = 2, overrides = {}) {
  return scored(userId, {
    riskLevel: 'LEARNING',
    scoredOn: 'policy',
    deviationScore: 0,
    components: {},
    learning: { activeDaysObserved, activeDaysRequired: 7, hasBaseline: true },
    ...overrides,
  });
}

function mockUeba(events, profiles) {
  api.get.mockImplementation((url) => {
    if (url.startsWith('/api/ueba/events')) {
      return Promise.resolve({ data: { events, total: events.length } });
    }
    const id = url.split('/').pop();
    const found = profiles.find((p) => p.userId === id);
    return found ? Promise.resolve({ data: found }) : Promise.reject(new Error('none'));
  });
}

beforeEach(() => vi.clearAllMocks());

describe('UEBA learning state', () => {
  test('a thin baseline shows progress instead of a risk percentage', async () => {
    // "We have not observed this person enough to say" is a different claim
    // from "this person is behaving normally", and the card has to make that
    // difference visible rather than showing a reassuring green LOW.
    mockUeba([event('newbie')], [learning('newbie', 2)]);
    render(<UEBA />);

    expect(await screen.findByText('LEARNING')).toBeInTheDocument();
    expect(screen.getByText('Building baseline')).toBeInTheDocument();
    expect(screen.getByText(/2\/7/)).toBeInTheDocument();
    expect(screen.queryByText('Live risk score')).not.toBeInTheDocument();
  });

  test('no metric breakdown is shown while learning', async () => {
    // The components are deliberately not computed -- showing "4 of 4 outside
    // 12-12h" would describe the sample size, not the person.
    mockUeba([event('newbie')], [learning('newbie', 1)]);
    render(<UEBA />);

    await screen.findByText('LEARNING');
    expect(screen.getByText(/not enough observed activity/i)).toBeInTheDocument();
    expect(screen.queryByText('Why this score')).not.toBeInTheDocument();
  });

  test('an established user shows a real score and its breakdown', async () => {
    mockUeba([event('alice')], [scored('alice')]);
    render(<UEBA />);

    expect(await screen.findByText('LOW')).toBeInTheDocument();
    expect(screen.getByText('Live risk score')).toBeInTheDocument();
    expect(screen.getByText('Why this score')).toBeInTheDocument();
  });

  test('a policy violation during learning shows a real band AND the caveat', async () => {
    // The hole an earlier version of the learning gate opened: LEARNING
    // replaced the band, so a 4 GB dump at 3am on someone's second day
    // rendered as a calm grey card. Both facts are true at once and both
    // must be on screen.
    mockUeba(
      [event('newbie')],
      [learning('newbie', 2, { riskLevel: 'HIGH', liveRiskScore: 0.6, eventBonus: 0.3, priorityBoost: 0.3 })],
    );
    render(<UEBA />);

    expect(await screen.findByText('HIGH')).toBeInTheDocument();
    expect(screen.getByText('Live risk score')).toBeInTheDocument();
    expect(screen.getByText(/scored on policy violations only/i)).toBeInTheDocument();
    expect(screen.getByText(/deviation scoring is not active yet/i)).toBeInTheDocument();
  });

  test('the caveat is absent for an established user', async () => {
    mockUeba([event('alice')], [scored('alice')]);
    render(<UEBA />);

    await screen.findByText('LOW');
    expect(screen.queryByText(/scored on policy violations only/i)).not.toBeInTheDocument();
  });
});

describe('UEBA page', () => {
  test('renders a card per distinct user', async () => {
    mockUeba(
      [event('alice'), event('alice'), event('bob')],
      [scored('alice'), scored('bob')],
    );
    render(<UEBA />);

    // The user id appears on the profile card AND in the events table, so
    // assert on presence rather than uniqueness.
    expect((await screen.findAllByText('alice')).length).toBeGreaterThan(0);
    expect(screen.getAllByText('bob').length).toBeGreaterThan(0);
  });

  test('shows the working-hours window from the baseline', async () => {
    mockUeba([event('alice')], [scored('alice')]);
    render(<UEBA />);
    expect(await screen.findByText('9–17h')).toBeInTheDocument();
  });

  test('a profile that fails to load does not blank the page', async () => {
    // One 404 among many users must not take the whole view down.
    mockUeba([event('alice'), event('ghost')], [scored('alice')]);
    const { container } = render(<UEBA />);

    expect((await screen.findAllByText('alice')).length).toBeGreaterThan(0);
    // 'ghost' still appears in the events table -- what must not exist is a
    // PROFILE CARD for it, since its risk-score request failed.
    await waitFor(() =>
      expect(container.querySelectorAll('.card').length).toBeGreaterThan(0));
    const cardText = [...container.querySelectorAll('.card')]
      .map((c) => c.textContent).join(' ');
    expect(cardText).toContain('alice');
    expect(cardText).not.toContain('Building baseline');
  });

  test('shows an empty state when there is no behaviour data', async () => {
    mockUeba([], []);
    render(<UEBA />);
    await waitFor(() => expect(api.get).toHaveBeenCalled());
    expect(await screen.findByText(/no behaviou?r/i)).toBeInTheDocument();
  });
});
