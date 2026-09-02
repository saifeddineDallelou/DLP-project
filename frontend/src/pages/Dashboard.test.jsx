import { render, screen, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, test, vi } from 'vitest';

vi.mock('../services/api.js', () => ({
  default: { get: vi.fn(), post: vi.fn(), put: vi.fn(), patch: vi.fn(), delete: vi.fn() },
}));

import api from '../services/api.js';
import Dashboard from './Dashboard.jsx';

function incident(overrides = {}) {
  return {
    id: overrides.id ?? `inc-${Math.random()}`,
    severity: 'CRITICAL',
    channel: 'CLIPBOARD',
    status: 'OPEN',
    riskScore: 0.9,
    createdAt: new Date().toISOString(),
    agent: { id: 'a1', hostname: 'SPIDEYPC' },
    policy: { id: 'p1', name: 'PCI-DSS' },
    ...overrides,
  };
}

function agent(overrides = {}) {
  return {
    id: overrides.id ?? 'ag-1',
    hostname: 'SPIDEYPC',
    os: 'Windows 11',
    status: 'ACTIVE',
    lastSeen: new Date().toISOString(),
    ...overrides,
  };
}

/** The dashboard fans out across several endpoints; route each by URL. */
function mockDashboard({ incidents = [], agents = [], openTotal = 0 } = {}) {
  api.get.mockImplementation((url) => {
    if (url.startsWith('/api/agents')) return Promise.resolve({ data: agents });
    if (url.includes('status=OPEN')) {
      return Promise.resolve({ data: { incidents: [], total: openTotal } });
    }
    if (url.startsWith('/api/incidents')) {
      return Promise.resolve({ data: { incidents, total: incidents.length } });
    }
    return Promise.resolve({ data: { incidents: [], total: 0 } });
  });
}

beforeEach(() => vi.clearAllMocks());

describe('Dashboard page', () => {
  test('renders without throwing when every source is empty', async () => {
    // A fresh install has no incidents and no agents. The dashboard is the
    // first page anyone sees, so it must survive that rather than crashing
    // on a reduce over an empty array.
    mockDashboard();
    render(<Dashboard />);
    await waitFor(() => expect(api.get).toHaveBeenCalled());
    expect(document.body.textContent.length).toBeGreaterThan(0);
  });

  test('reads incidents and agents from the API', async () => {
    mockDashboard({ incidents: [incident()], agents: [agent()] });
    render(<Dashboard />);

    await waitFor(() => {
      const urls = api.get.mock.calls.map(([u]) => u);
      expect(urls.some((u) => u.startsWith('/api/incidents'))).toBe(true);
      expect(urls.some((u) => u.startsWith('/api/agents'))).toBe(true);
    });
  });

  test('surfaces the open-incident count', async () => {
    mockDashboard({ incidents: [incident(), incident({ id: 'i2' })], agents: [agent()], openTotal: 7 });
    const { container } = render(<Dashboard />);
    await waitFor(() => expect(container.textContent).toContain('7'));
  });

  test('shows a recent incident by hostname', async () => {
    mockDashboard({ incidents: [incident()], agents: [agent()] });
    const { container } = render(<Dashboard />);
    await waitFor(() => expect(container.textContent).toContain('SPIDEYPC'));
  });

  test('a failed request does not leave the page stuck loading', async () => {
    api.get.mockRejectedValue(new Error('network'));
    const { container } = render(<Dashboard />);
    await waitFor(() =>
      expect(container.querySelector('.animate-spin')).toBeNull());
  });
});
