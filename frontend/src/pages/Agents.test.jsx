import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, test, vi } from 'vitest';

vi.mock('../services/api.js', () => ({
  default: { get: vi.fn(), post: vi.fn(), patch: vi.fn(), delete: vi.fn() },
}));

import api from '../services/api.js';
import Agents from './Agents.jsx';

function agent(overrides = {}) {
  return {
    id: overrides.id ?? 'ag-1',
    hostname: 'SPIDEYPC',
    os: 'Windows 11',
    version: '1.0.0',
    status: 'ACTIVE',
    lastSeen: '2026-09-02T10:00:00Z',
    createdAt: '2026-08-18T09:00:00Z',
    ...overrides,
  };
}

beforeEach(() => vi.clearAllMocks());

describe('Agents page', () => {
  test('lists enrolled endpoints with hostname, OS and status', async () => {
    api.get.mockResolvedValue({ data: [agent()] });
    render(<Agents />);

    expect(await screen.findByText('SPIDEYPC')).toBeInTheDocument();
    expect(screen.getByText('Windows 11')).toBeInTheDocument();
    expect(screen.getByText('ACTIVE')).toBeInTheDocument();
  });

  test('shows every enrolled agent', async () => {
    api.get.mockResolvedValue({
      data: [agent(), agent({ id: 'ag-2', hostname: 'LAPTOP-02', status: 'OFFLINE' })],
    });
    render(<Agents />);

    expect(await screen.findByText('SPIDEYPC')).toBeInTheDocument();
    expect(screen.getByText('LAPTOP-02')).toBeInTheDocument();
    expect(screen.getByText('OFFLINE')).toBeInTheDocument();
  });

  test('filters by hostname', async () => {
    const user = userEvent.setup();
    api.get.mockResolvedValue({
      data: [agent(), agent({ id: 'ag-2', hostname: 'LAPTOP-02' })],
    });
    render(<Agents />);

    await screen.findByText('SPIDEYPC');
    await user.type(screen.getByPlaceholderText(/search by hostname/i), 'LAPTOP');

    await waitFor(() => expect(screen.queryByText('SPIDEYPC')).not.toBeInTheDocument());
    expect(screen.getByText('LAPTOP-02')).toBeInTheDocument();
  });

  test('shows an empty state when nothing is enrolled', async () => {
    api.get.mockResolvedValue({ data: [] });
    render(<Agents />);
    await waitFor(() => expect(api.get).toHaveBeenCalled());
    expect(await screen.findByText(/no agents/i)).toBeInTheDocument();
  });

  test('a failed request does not leave a spinner up forever', async () => {
    // The page has to settle into SOME terminal state; hanging on the
    // spinner is indistinguishable from a slow network and tells the
    // operator nothing.
    api.get.mockRejectedValue(new Error('network'));
    const { container } = render(<Agents />);
    await waitFor(() =>
      expect(container.querySelector('[data-testid="spinner"], .animate-spin')).toBeNull());
  });
});
