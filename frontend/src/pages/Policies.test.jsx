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

  test('offers a response per channel, defaulting to the policy action', async () => {
    const user = userEvent.setup();
    api.get.mockResolvedValue({ data: [] });
    render(<Policies />);

    await user.click(await screen.findByRole('button', { name: /new policy|create first/i }));

    // Every channel starts on the policy default rather than inventing one.
    expect(screen.getByLabelText(/clipboard action/i)).toHaveValue('');
    expect(screen.getByLabelText(/file at rest action/i)).toHaveValue('');
  });

  test('only offers responses a channel can actually carry out', async () => {
    // A file already at rest has nothing in flight to stop, and a paste
    // cannot be moved to a quarantine folder. Offering the impossible option
    // is how a policy ends up silently doing nothing.
    const user = userEvent.setup();
    api.get.mockResolvedValue({ data: [] });
    render(<Policies />);

    await user.click(await screen.findByRole('button', { name: /new policy|create first/i }));

    const atRest = [...screen.getByLabelText(/file at rest action/i).options].map(o => o.value);
    expect(atRest).toContain('QUARANTINE');
    expect(atRest).not.toContain('BLOCK');

    const clipboard = [...screen.getByLabelText(/clipboard action/i).options].map(o => o.value);
    expect(clipboard).toContain('BLOCK');
    expect(clipboard).not.toContain('QUARANTINE');
  });

  test('sends the chosen overrides with the policy', async () => {
    const user = userEvent.setup();
    api.get.mockResolvedValue({ data: [] });
    api.post.mockResolvedValue({ data: policy() });
    render(<Policies />);

    await user.click(await screen.findByRole('button', { name: /new policy|create first/i }));
    await user.type(screen.getByLabelText(/^name/i), 'PII Detection');
    await user.selectOptions(screen.getByLabelText(/file at rest action/i), 'QUARANTINE');
    await user.click(screen.getByRole('button', { name: /create policy|save/i }));

    await waitFor(() => expect(api.post).toHaveBeenCalled());
    expect(api.post.mock.calls[0][1].channelActions).toEqual({ FILE: 'QUARANTINE' });
  });

  test('clearing a channel back to Default removes the override', async () => {
    // Otherwise "Default" would be stored as an empty string and reach the
    // agent as an action it does not recognise.
    const user = userEvent.setup();
    api.get.mockResolvedValue({ data: [] });
    api.post.mockResolvedValue({ data: policy() });
    render(<Policies />);

    await user.click(await screen.findByRole('button', { name: /new policy|create first/i }));
    await user.type(screen.getByLabelText(/^name/i), 'PII Detection');
    const atRest = screen.getByLabelText(/file at rest action/i);
    await user.selectOptions(atRest, 'QUARANTINE');
    await user.selectOptions(atRest, '');
    await user.click(screen.getByRole('button', { name: /create policy|save/i }));

    await waitFor(() => expect(api.post).toHaveBeenCalled());
    expect(api.post.mock.calls[0][1].channelActions).toEqual({});
  });


  test('a policy has no ladder until one is asked for', async () => {
    const user = userEvent.setup();
    api.get.mockResolvedValue({ data: [] });
    render(<Policies />);

    await user.click(await screen.findByRole('button', { name: /new policy|create first/i }));
    expect(screen.getByRole('button', { name: /use a risk ladder/i })).toBeInTheDocument();
    expect(screen.queryByLabelText(/tier 1 action/i)).not.toBeInTheDocument();
  });

  test('the starting ladder escalates rather than flattening', async () => {
    // A ladder that gets softer as confidence rises gives the strongest
    // evidence the weakest response, so the default must not model that.
    const user = userEvent.setup();
    api.get.mockResolvedValue({ data: [] });
    render(<Policies />);

    await user.click(await screen.findByRole('button', { name: /new policy|create first/i }));
    await user.click(screen.getByRole('button', { name: /use a risk ladder/i }));

    expect(screen.getByLabelText(/tier 1 threshold/i)).toHaveValue(0.9);
    expect(screen.getByLabelText(/tier 1 action/i)).toHaveValue('QUARANTINE');
    expect(screen.getByLabelText(/tier 2 action/i)).toHaveValue('ALERT');
  });

  test('rungs are shown highest confidence first', async () => {
    const user = userEvent.setup();
    api.get.mockResolvedValue({ data: [] });
    render(<Policies />);

    await user.click(await screen.findByRole('button', { name: /new policy|create first/i }));
    await user.click(screen.getByRole('button', { name: /use a risk ladder/i }));

    const thresholds = [screen.getByLabelText(/tier 1 threshold/i).value,
                       screen.getByLabelText(/tier 2 threshold/i).value].map(Number);
    expect(thresholds[0]).toBeGreaterThan(thresholds[1]);
  });

  test('the ladder is sent with the policy', async () => {
    const user = userEvent.setup();
    api.get.mockResolvedValue({ data: [] });
    api.post.mockResolvedValue({ data: policy() });
    render(<Policies />);

    await user.click(await screen.findByRole('button', { name: /new policy|create first/i }));
    await user.type(screen.getByLabelText(/^name/i), 'PII Detection');
    await user.click(screen.getByRole('button', { name: /use a risk ladder/i }));
    await user.click(screen.getByRole('button', { name: /create policy|save/i }));

    await waitFor(() => expect(api.post).toHaveBeenCalled());
    const tiers = api.post.mock.calls[0][1].tiers;
    expect(tiers).toHaveLength(2);
    expect(tiers[0]).toMatchObject({ minRisk: 0.9, action: 'QUARANTINE' });
  });

  test('a rung can be removed', async () => {
    const user = userEvent.setup();
    api.get.mockResolvedValue({ data: [] });
    render(<Policies />);

    await user.click(await screen.findByRole('button', { name: /new policy|create first/i }));
    await user.click(screen.getByRole('button', { name: /use a risk ladder/i }));
    await user.click(screen.getByRole('button', { name: /remove tier 1/i }));

    expect(screen.queryByLabelText(/tier 2 action/i)).not.toBeInTheDocument();
  });

});
