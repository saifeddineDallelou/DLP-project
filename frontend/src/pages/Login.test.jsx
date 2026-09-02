import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, test, vi } from 'vitest';

const login = vi.fn();
const navigate = vi.fn();

vi.mock('../context/AuthContext.jsx', () => ({ useAuth: () => ({ login }) }));
vi.mock('react-router-dom', () => ({ useNavigate: () => navigate }));

import Login from './Login.jsx';

beforeEach(() => {
  vi.clearAllMocks();
  login.mockReset();
  navigate.mockReset();
});

describe('Login page', () => {
  test('signs in and goes to the dashboard', async () => {
    const user = userEvent.setup();
    login.mockResolvedValue({});
    render(<Login />);

    await user.type(screen.getByPlaceholderText('admin@dlp.local'), 'admin@dlp.local');
    await user.type(screen.getByPlaceholderText('••••••••'), 'Admin123!');
    await user.click(screen.getByRole('button', { name: /sign in|log ?in/i }));

    await waitFor(() => expect(login).toHaveBeenCalledWith('admin@dlp.local', 'Admin123!'));
    expect(navigate).toHaveBeenCalledWith('/dashboard', { replace: true });
  });

  test('names the real problem when the backend is unreachable', async () => {
    // "Authentication failed" for a connection refused sends the operator
    // hunting for a password problem that does not exist. This is the first
    // screen anyone sees on a fresh install, and the backend not running is
    // the single most likely reason it does not work.
    const user = userEvent.setup();
    login.mockRejectedValue({ request: {}, response: undefined });
    render(<Login />);

    await user.type(screen.getByPlaceholderText('admin@dlp.local'), 'a@b.c');
    await user.type(screen.getByPlaceholderText('••••••••'), 'pw');
    await user.click(screen.getByRole('button', { name: /sign in|log ?in/i }));

    expect(await screen.findByText(/cannot reach the server/i)).toBeInTheDocument();
    expect(navigate).not.toHaveBeenCalled();
  });

  test('shows the server’s message for bad credentials', async () => {
    const user = userEvent.setup();
    login.mockRejectedValue({ response: { data: { error: 'Invalid credentials' } } });
    render(<Login />);

    await user.type(screen.getByPlaceholderText('admin@dlp.local'), 'a@b.c');
    await user.type(screen.getByPlaceholderText('••••••••'), 'wrong');
    await user.click(screen.getByRole('button', { name: /sign in|log ?in/i }));

    expect(await screen.findByText('Invalid credentials')).toBeInTheDocument();
    expect(navigate).not.toHaveBeenCalled();
  });

  test('the password is masked until deliberately revealed', async () => {
    const user = userEvent.setup();
    render(<Login />);

    const pw = screen.getByPlaceholderText('••••••••');
    expect(pw).toHaveAttribute('type', 'password');

    // The reveal toggle is the only unlabelled control beside the field.
    const toggle = pw.parentElement.querySelector('button');
    if (toggle) {
      await user.click(toggle);
      expect(pw).toHaveAttribute('type', 'text');
    }
  });
});
