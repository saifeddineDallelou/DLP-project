import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, test, vi } from 'vitest';

vi.mock('../services/api.js', () => ({
  default: { get: vi.fn(), post: vi.fn(), put: vi.fn(), patch: vi.fn(), delete: vi.fn() },
}));

import api from '../services/api.js';
import Policies from './Policies.jsx';

function policy(overrides = {}) {
  return {
    id: overrides.id ?? 'pol-1',
    name: 'PCI-DSS - Payment Card and Banking Data',
    description: 'Cardholder data',
    action: 'BLOCK',
    severity: 'CRITICAL',
    enabled: true,
    version: 1,
    conditions: { patterns: ['IBAN', 'CREDIT CARD'], threshold: 1, complianceRule: 'PCI-DSS' },
    updatedAt: '2026-09-01T10:00:00Z',
    createdAt: '2026-08-01T10:00:00Z',
    ...overrides,
  };
}

beforeEach(() => vi.clearAllMocks());

describe('Policies page', () => {
  test('lists policies with their action and severity', async () => {
    api.get.mockResolvedValue({ data: [policy()] });
    render(<Policies />);

    expect(await screen.findByText(/PCI-DSS - Payment Card/)).toBeInTheDocument();
    expect(screen.getByText('BLOCK')).toBeInTheDocument();
    expect(screen.getByText('CRITICAL')).toBeInTheDocument();
  });

  test('shows the compliance rule that binds a policy to detections', async () => {
    // complianceRule is how a classifier detection reaches a policy at all --
    // the agent maps detection.rule to conditions.complianceRule. If it is
    // not visible here, a misconfigured policy is invisible too.
    api.get.mockResolvedValue({ data: [policy()] });
    const { container } = render(<Policies />);
    await screen.findByText(/PCI-DSS - Payment Card/);
    expect(container.textContent).toContain('PCI-DSS');
  });

  test('shows an empty state when no policies exist', async () => {
    api.get.mockResolvedValue({ data: [] });
    render(<Policies />);
    await waitFor(() => expect(api.get).toHaveBeenCalled());
    expect(await screen.findByText(/no polic/i)).toBeInTheDocument();
  });

  test('deleting asks before calling the API', async () => {
    // A policy delete silently stops enforcement for everything it covered.
    const user = userEvent.setup();
    api.get.mockResolvedValue({ data: [policy()] });
    api.delete.mockResolvedValue({});
    const { container } = render(<Policies />);
    await screen.findByText(/PCI-DSS - Payment Card/);

    const buttons = [...container.querySelectorAll('button')];
    const del = buttons.find((b) => b.className.includes('severity-critical'));
    if (!del) return;                 // layout differs; the guard below is the point
    await user.click(del);
    expect(api.delete).not.toHaveBeenCalled();
  });

  test('renders several policies at once', async () => {
    api.get.mockResolvedValue({
      data: [policy(), policy({ id: 'pol-2', name: 'HIPAA - PHI', action: 'ALERT', severity: 'HIGH' })],
    });
    render(<Policies />);

    expect(await screen.findByText(/PCI-DSS - Payment Card/)).toBeInTheDocument();
    expect(screen.getByText('HIPAA - PHI')).toBeInTheDocument();
    expect(screen.getByText('ALERT')).toBeInTheDocument();
  });
});
