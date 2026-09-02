import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, test, vi } from 'vitest';

vi.mock('../services/api.js', () => ({
  default: { get: vi.fn(), post: vi.fn(), put: vi.fn(), patch: vi.fn(), delete: vi.fn() },
}));

import api from '../services/api.js';
import AppRules from './AppRules.jsx';

function rule(overrides = {}) {
  return {
    id: overrides.id ?? 'r-1',
    keyword: 'teamviewer',
    label: 'TeamViewer remote access',
    enabled: true,
    updatedAt: '2026-09-01T10:00:00Z',
    ...overrides,
  };
}

beforeEach(() => vi.clearAllMocks());

describe('AppRules page', () => {
  test('lists rules with keyword and label', async () => {
    api.get.mockResolvedValue({ data: [rule()] });
    render(<AppRules />);

    expect(await screen.findByText('teamviewer')).toBeInTheDocument();
    expect(screen.getByText('TeamViewer remote access')).toBeInTheDocument();
  });

  test('shows an empty state with a way out of it', async () => {
    api.get.mockResolvedValue({ data: [] });
    render(<AppRules />);

    expect(await screen.findByText(/no restricted-app rules yet/i)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /create first rule/i })).toBeInTheDocument();
  });

  test('will not save a rule missing its keyword or label', async () => {
    // Both are required: a rule with no keyword matches nothing, and one with
    // no label is unreadable in an incident.
    const user = userEvent.setup();
    api.get.mockResolvedValue({ data: [] });
    render(<AppRules />);

    await user.click(await screen.findByRole('button', { name: /create first rule/i }));
    await user.type(screen.getByPlaceholderText('e.g. teamviewer'), 'anydesk');
    // Label deliberately left blank, then submit: the form must not POST.
    await user.click(screen.getByRole('button', { name: /create rule/i }));
    expect(api.post).not.toHaveBeenCalled();
  });

  test('creates a rule from the form', async () => {
    const user = userEvent.setup();
    api.get.mockResolvedValue({ data: [] });
    api.post.mockResolvedValue({ data: rule({ keyword: 'anydesk' }) });
    render(<AppRules />);

    await user.click(await screen.findByRole('button', { name: /create first rule/i }));
    await user.type(screen.getByPlaceholderText('e.g. teamviewer'), 'anydesk');
    await user.type(screen.getByPlaceholderText('e.g. TeamViewer remote access'), 'AnyDesk');
    await user.click(screen.getByRole('button', { name: /create rule/i }));

    await waitFor(() => expect(api.post).toHaveBeenCalled());
    const [url, body] = api.post.mock.calls[0];
    expect(url).toBe('/api/app-rules');
    expect(body.keyword).toBe('anydesk');
    expect(body.label).toBe('AnyDesk');
  });

  test('toggling enabled persists immediately', async () => {
    const user = userEvent.setup();
    api.get.mockResolvedValue({ data: [rule()] });
    api.put.mockResolvedValue({ data: rule({ enabled: false }) });
    render(<AppRules />);

    await screen.findByText('teamviewer');
    const toggle = screen.getByRole('switch', { name: /enabled/i });
    await user.click(toggle);
    await waitFor(() => expect(api.put).toHaveBeenCalled());
  });
});
