import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, test, vi } from 'vitest';

vi.mock('../services/api.js', () => ({
  default: { get: vi.fn(), post: vi.fn(), put: vi.fn(), patch: vi.fn(), delete: vi.fn() },
}));

// The page reads the signed-in user to decide which triage controls to show,
// so it needs an auth context. Rendering the real provider would pull in
// token refresh and routing; the role is all this page actually consumes.
vi.mock('../context/AuthContext.jsx', () => ({
  useAuth: () => ({ user: { id: 'u1', email: 'admin@dlp.local', role: 'ADMIN' } }),
}));

import api from '../services/api.js';
import Incidents from './Incidents.jsx';

function incident(overrides = {}) {
  return {
    id: overrides.id ?? 'inc-1',
    severity: 'CRITICAL',
    channel: 'CLIPBOARD',
    status: 'OPEN',
    riskScore: 0.9,
    reviewRequested: false,
    adminNote: null,
    createdAt: '2026-09-02T09:00:00Z',
    agent: { id: 'a1', hostname: 'SPIDEYPC' },
    policy: { id: 'p1', name: 'PCI-DSS - Payment Card and Banking Data' },
    ...overrides,
  };
}

function mockIncidents(incidents, extra = {}) {
  api.get.mockResolvedValue({
    data: { incidents, total: incidents.length, page: 1, limit: 25, ...extra },
  });
}

beforeEach(() => vi.clearAllMocks());

describe('Incidents page', () => {
  test('lists incidents with severity, channel and agent', async () => {
    mockIncidents([incident()]);
    const renderResult = render(<Incidents />);

    // CRITICAL is also a <option> in the severity filter, so read the row.
    expect(await screen.findByText('SPIDEYPC')).toBeInTheDocument();
    const { container } = renderResult;
    const row = container.querySelector('tbody tr').textContent;
    expect(row).toContain('CRITICAL');
    expect(row).toContain('CLIPBOARD');
  });

  test('shows the policy an incident violated', async () => {
    // Without it an analyst cannot tell why the incident was raised, only
    // that it was.
    mockIncidents([incident()]);
    render(<Incidents />);
    expect(await screen.findByText(/PCI-DSS - Payment Card/)).toBeInTheDocument();
  });

  test('shows an empty state when nothing matches', async () => {
    mockIncidents([]);
    render(<Incidents />);
    await waitFor(() => expect(api.get).toHaveBeenCalled());
    expect(await screen.findByText(/no incidents found/i)).toBeInTheDocument();
  });

  test('renders incidents of differing severity together', async () => {
    mockIncidents([
      incident(),
      incident({ id: 'inc-2', severity: 'LOW', channel: 'FILE', agent: { id: 'a2', hostname: 'LAPTOP-02' } }),
    ]);
    const { container } = render(<Incidents />);

    await waitFor(() =>
      expect(container.querySelectorAll('tbody tr').length).toBe(2));
    const rows = [...container.querySelectorAll('tbody tr')].map((r) => r.textContent);
    expect(rows[0]).toContain('CRITICAL');
    expect(rows[1]).toContain('LOW');
  });

  test('a severity filter is sent to the API rather than applied client-side', async () => {
    // Filtering in the browser would only ever filter the current page, which
    // silently lies about how many incidents match.
    const user = userEvent.setup();
    mockIncidents([incident()]);
    render(<Incidents />);
    await screen.findByText('SPIDEYPC');

    // [0] is the status filter, [1] the severity filter.
    const selects = screen.getAllByRole('combobox');
    await user.selectOptions(selects[1], 'CRITICAL');

    await waitFor(() => {
      const urls = api.get.mock.calls.map(([u]) => u);
      expect(urls.some((u) => u.includes('CRITICAL'))).toBe(true);
    });
  });

  test('opening an incident shows its detail', async () => {
    const user = userEvent.setup();
    mockIncidents([incident()]);
    const { container } = render(<Incidents />);

    await screen.findByText('SPIDEYPC');
    await user.click(container.querySelector('tbody tr'));
    await waitFor(() =>
      expect(screen.getAllByText(/PCI-DSS - Payment Card/).length).toBeGreaterThan(0));
  });
});
