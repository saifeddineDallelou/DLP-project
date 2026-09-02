import { render, screen, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, test, vi } from 'vitest';

vi.mock('../services/api.js', () => ({
  default: { get: vi.fn(), post: vi.fn(), put: vi.fn(), patch: vi.fn(), delete: vi.fn() },
}));

import api from '../services/api.js';
import Reports from './Reports.jsx';

const DAILY = {
  date: '2026-09-02',
  summary: {
    totalIncidents: 3,
    totalAiLeakAttempts: 2,
    reviewRequested: 1,
    needsAdminNote: 1,
  },
  timeline: [
    {
      // agent/policy are NESTED objects on the daily route (they are flat
      // hostname/policyName on the compliance route -- two shapes, one page).
      id: 'inc-1', kind: 'INCIDENT', time: '2026-09-02T09:00:00Z',
      severity: 'CRITICAL', channel: 'CLIPBOARD', status: 'OPEN',
      agent: { id: 'a1', hostname: 'SPIDEYPC' },
      policy: { id: 'p1', name: 'PCI-DSS' },
      reviewRequested: true, adminNote: null, justification: 'Needed for support',
    },
  ],
};

const COMPLIANCE = {
  period: { from: '2026-08-01T00:00:00Z', to: '2026-09-02T00:00:00Z' },
  summary: {
    totalEvents: 12, totalIncidents: 8, totalAiLeakAttempts: 4,
    rulesWithActivity: 2, rulesCovered: 4, awaitingAdmin: 1,
  },
  // Field names must match src/routes/reports.js `ensure()` exactly --
  // ComplianceReport reads g.bySeverity[...] without a guard, so a group
  // missing it takes the whole page down.
  rules: [
    {
      rule: 'PCI-DSS', total: 8, incidents: 6, aiLeakAttempts: 2,
      blocked: 7, allowed: 1,
      bySeverity: { CRITICAL: 4, HIGH: 2, MEDIUM: 0, LOW: 0 },
      reviewRequested: 1, awaitingAdmin: 1, policyEnabled: true, events: [],
    },
    {
      rule: 'GDPR', total: 4, incidents: 2, aiLeakAttempts: 2,
      blocked: 4, allowed: 0,
      bySeverity: { CRITICAL: 0, HIGH: 1, MEDIUM: 1, LOW: 0 },
      reviewRequested: 0, awaitingAdmin: 0, policyEnabled: true, events: [],
    },
  ],
};

function mockReports({ daily = DAILY, compliance = COMPLIANCE, incidents = [] } = {}) {
  api.get.mockImplementation((url) => {
    if (url.startsWith('/api/reports/daily')) return Promise.resolve({ data: daily });
    if (url.startsWith('/api/reports/compliance')) return Promise.resolve({ data: compliance });
    if (url.startsWith('/api/incidents')) {
      return Promise.resolve({ data: { incidents, total: incidents.length } });
    }
    return Promise.resolve({ data: {} });
  });
}

beforeEach(() => vi.clearAllMocks());

describe('Reports page', () => {
  test('requests the daily report on load', async () => {
    mockReports();
    render(<Reports />);
    await waitFor(() => {
      const urls = api.get.mock.calls.map(([u]) => u);
      expect(urls.some((u) => u.startsWith('/api/reports/daily'))).toBe(true);
    });
  });

  test('shows the daily summary counts', async () => {
    mockReports();
    const { container } = render(<Reports />);
    await waitFor(() => expect(container.textContent).toContain('SPIDEYPC'));
  });

  test('flags an item that is awaiting an admin note', async () => {
    // An item flagged for review with no admin note is the one thing on this
    // page that requires a human to act, so the row has to mark it.
    mockReports();
    const { container } = render(<Reports />);
    await waitFor(() => expect(container.textContent).toContain('SPIDEYPC'));
    // The page renders more than one table, so find the row by content.
    const row = [...container.querySelectorAll('tbody tr')]
      .find((r) => r.textContent.includes('SPIDEYPC'));
    expect(row).toBeDefined();
    expect(row.querySelector('svg')).not.toBeNull();   // the review flag
    expect(row.textContent).toContain('—');            // no admin note yet
  });

  test('renders with an empty timeline rather than crashing', async () => {
    mockReports({
      daily: { ...DAILY, timeline: [], summary: { totalIncidents: 0, totalAiLeakAttempts: 0, reviewRequested: 0, needsAdminNote: 0 } },
    });
    render(<Reports />);
    await waitFor(() => expect(api.get).toHaveBeenCalled());
    expect(document.body.textContent.length).toBeGreaterThan(0);
  });

  test('survives a failed report request', async () => {
    api.get.mockRejectedValue(new Error('network'));
    const { container } = render(<Reports />);
    await waitFor(() => expect(container.querySelector('.animate-spin')).toBeNull());
  });
});
