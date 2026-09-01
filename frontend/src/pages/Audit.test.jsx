import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, test, vi } from 'vitest';

vi.mock('../services/api.js', () => ({
  default: { get: vi.fn(), post: vi.fn(), patch: vi.fn(), delete: vi.fn() },
}));

import api from '../services/api.js';
import Audit from './Audit.jsx';

const ACTIONS = {
  actions: ['LOGIN', 'RECOMPUTE_BEHAVIOR_BASELINE', 'UPDATE_POLICY'],
  resources: ['auth', 'policy', 'user_behavior_baseline'],
};

function log(overrides = {}) {
  return {
    id: overrides.id ?? 'log-1',
    action: 'UPDATE_POLICY',
    resource: 'policy',
    resourceId: 'pol-1',
    ipAddress: '127.0.0.1',
    createdAt: '2026-01-15T10:00:00Z',
    metadata: {},
    user: { id: 'u1', email: 'admin@dlp.local', role: 'ADMIN' },
    ...overrides,
  };
}

function mockAudit(logs, extra = {}) {
  api.get.mockImplementation((url) => {
    if (url.startsWith('/api/audit/actions')) return Promise.resolve({ data: ACTIONS });
    return Promise.resolve({
      data: { total: logs.length, page: 1, limit: 25, pages: 1, logs, ...extra },
    });
  });
}

beforeEach(() => vi.clearAllMocks());

describe('who performed the action', () => {
  test('shows the account that did it', async () => {
    mockAudit([log()]);
    render(<Audit />);
    expect(await screen.findByText('admin@dlp.local')).toBeInTheDocument();
  });

  test('an automated write is labelled System, not a deleted account', async () => {
    // The bug this covers: a scheduled baseline refresh records a NULL actor
    // on purpose -- that is how an automated write is told apart from an
    // admin doing the same thing by hand. Rendering it as "deleted user"
    // implied an account had vanished.
    mockAudit([log({
      user: null,
      action: 'RECOMPUTE_BEHAVIOR_BASELINE',
      resource: 'user_behavior_baseline',
      metadata: { source: 'SCHEDULED', reason: 'STALE', days: 30 },
    })]);

    render(<Audit />);

    expect(await screen.findByText('System')).toBeInTheDocument();
    expect(screen.getByText('automated')).toBeInTheDocument();
    expect(screen.queryByText(/deleted/i)).not.toBeInTheDocument();
  });

  test('a null actor with no source is still a deleted account', async () => {
    // The other half: a row outlives the account that created it. Losing the
    // actor is better than losing the record, but it must not be confused
    // with a system action.
    mockAudit([log({ user: null, metadata: {} })]);

    render(<Audit />);

    expect(await screen.findByText(/deleted account/i)).toBeInTheDocument();
    expect(screen.queryByText('System')).not.toBeInTheDocument();
  });
});

describe('the trail itself', () => {
  test('renders the recorded action and resource', async () => {
    mockAudit([log({ action: 'DELETE_AGENT', resource: 'agent', resourceId: 'agent-9' })]);
    render(<Audit />);

    expect(await screen.findByText('DELETE_AGENT')).toBeInTheDocument();
    expect(screen.getByText('agent')).toBeInTheDocument();
  });

  test('says plainly when the trail is empty', async () => {
    mockAudit([]);
    render(<Audit />);
    expect(await screen.findByText(/no audit entries yet/i)).toBeInTheDocument();
  });

  test('offers details only for a row that recorded any', async () => {
    mockAudit([
      log({ id: 'a', metadata: { hostname: 'FINANCE-WS-04' } }),
      log({ id: 'b', metadata: {} }),
    ]);
    render(<Audit />);

    await screen.findByText('DELETE_AGENT').catch(() => {});
    const buttons = await screen.findAllByRole('button', { name: /details/i });
    expect(buttons).toHaveLength(1);
  });

  test('a detail view shows what was recorded', async () => {
    mockAudit([log({ metadata: { hostname: 'FINANCE-WS-04', os: 'Windows 11' } })]);
    render(<Audit />);

    await userEvent.click(await screen.findByRole('button', { name: /details/i }));

    expect(await screen.findByText(/FINANCE-WS-04/)).toBeInTheDocument();
  });
});

describe('filters', () => {
  test('are built from the values actually present, not a hardcoded list', async () => {
    // A hardcoded filter list silently drifts as new audited actions are
    // added, and an action nobody can filter for is close to unrecorded.
    mockAudit([log()]);
    render(<Audit />);

    await waitFor(() => expect(api.get).toHaveBeenCalledWith('/api/audit/actions'));
    expect(await screen.findByRole('option', { name: 'RECOMPUTE_BEHAVIOR_BASELINE' })).toBeInTheDocument();
  });

  test('selecting a resource re-queries the server', async () => {
    mockAudit([log()]);
    render(<Audit />);
    await screen.findByText('admin@dlp.local');

    // Queried by its visible label, which also asserts the filter controls
    // are actually labelled -- a bare <select> is unusable with a screen
    // reader and indistinguishable from its neighbour.
    await userEvent.selectOptions(screen.getByLabelText(/resource/i), 'policy');

    await waitFor(() => {
      const urls = api.get.mock.calls.map(([u]) => u);
      expect(urls.some((u) => u.includes('resource=policy'))).toBe(true);
    });
  });
});
