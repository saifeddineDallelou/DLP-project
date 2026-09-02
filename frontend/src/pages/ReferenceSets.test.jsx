import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, test, vi } from 'vitest';

vi.mock('../services/api.js', () => ({
  default: { get: vi.fn(), post: vi.fn(), patch: vi.fn(), delete: vi.fn() },
}));

import api from '../services/api.js';
import ReferenceSets, { parseCsv } from './ReferenceSets.jsx';

function set(overrides = {}) {
  return {
    name: 'customers',
    rule: 'GDPR',
    columns: { name: 3, city: 2, ref: 3 },
    totalValues: 8,
    minFields: 2,
    rowCount: 3,
    ...overrides,
  };
}

beforeEach(() => vi.clearAllMocks());

// The CSV parser is where real customer records are turned into rows, so it
// is worth pinning directly rather than only through the form.
describe('parseCsv', () => {
  test('maps a header row onto each record', () => {
    expect(parseCsv('name,city\nSarah Okafor,Manchester')).toEqual([
      { name: 'Sarah Okafor', city: 'Manchester' },
    ]);
  });

  test('handles a quoted field containing a comma', () => {
    // A customer name containing a comma is not an edge case.
    expect(parseCsv('name,address\n"Okafor, Sarah","12 High St, Leeds"')).toEqual([
      { name: 'Okafor, Sarah', address: '12 High St, Leeds' },
    ]);
  });

  test('handles an escaped quote inside a quoted field', () => {
    expect(parseCsv('name\n"The ""Big"" Co"')).toEqual([{ name: 'The "Big" Co' }]);
  });

  test('omits empty cells rather than indexing blanks', () => {
    // An empty string would otherwise be hashed and become a value that
    // matches every document with a blank in it.
    expect(parseCsv('name,city\nSarah,')).toEqual([{ name: 'Sarah' }]);
  });

  test('ignores blank lines and trailing newlines', () => {
    expect(parseCsv('name\nSarah\n\nDimitri\n')).toEqual([{ name: 'Sarah' }, { name: 'Dimitri' }]);
  });

  test('rejects a file with no data rows', () => {
    expect(() => parseCsv('name,city')).toThrow(/header row and at least one data row/i);
  });

  test('rejects an unnamed column', () => {
    expect(() => parseCsv('name,,city\na,b,c')).toThrow(/column needs a name/i);
  });

  test('rejects duplicate column names', () => {
    // Two columns of the same name would silently collapse into one.
    expect(() => parseCsv('name,name\na,b')).toThrow(/unique/i);
  });
});

describe('ReferenceSets page', () => {
  test('lists configured sets with their columns', async () => {
    api.get.mockResolvedValue({ data: [set()] });
    render(<ReferenceSets />);

    expect(await screen.findByText('customers')).toBeInTheDocument();
    expect(screen.getByText(/3 records/)).toBeInTheDocument();
    expect(screen.getByText(/8 indexed values/)).toBeInTheDocument();
    expect(screen.getByText('GDPR')).toBeInTheDocument();
  });

  test('says whether a set is correlated or per-value', async () => {
    api.get.mockResolvedValue({ data: [set({ minFields: 2 }), set({ name: 'cards', minFields: 1 })] });
    render(<ReferenceSets />);

    expect(await screen.findByText(/2 fields of one record must match/)).toBeInTheDocument();
    expect(screen.getByText(/any single indexed value matches/i)).toBeInTheDocument();
  });

  test('shows an empty state when nothing is indexed', async () => {
    api.get.mockResolvedValue({ data: [] });
    render(<ReferenceSets />);
    expect(await screen.findByText(/no reference sets yet/i)).toBeInTheDocument();
  });

  test('names the classifier when it is the service that is down', async () => {
    // An empty page would imply no sets are configured, which is a different
    // and much more reassuring claim than "we cannot read them right now".
    api.get.mockRejectedValue({ response: { status: 503 } });
    render(<ReferenceSets />);
    expect(await screen.findByText(/classifier service unavailable/i)).toBeInTheDocument();
  });

  test('uploads parsed rows and refreshes the list', async () => {
    const user = userEvent.setup();
    api.get.mockResolvedValue({ data: [] });
    api.post.mockResolvedValue({ data: set() });
    render(<ReferenceSets />);

    await user.click(await screen.findByRole('button', { name: /index first set/i }));
    await user.type(screen.getByLabelText(/set name/i), 'customers');
    await user.type(
      screen.getByLabelText(/records/i),
      'name,city\nSarah Okafor,Manchester\nDimitri Volkov,Manchester',
    );
    await user.click(screen.getByRole('button', { name: /^index set$/i }));

    await waitFor(() => expect(api.post).toHaveBeenCalled());
    const [url, body] = api.post.mock.calls[0];
    expect(url).toBe('/api/edm');
    expect(body.name).toBe('customers');
    expect(body.rows).toEqual([
      { name: 'Sarah Okafor', city: 'Manchester' },
      { name: 'Dimitri Volkov', city: 'Manchester' },
    ]);
    // The list is re-read so the new set appears without a manual refresh.
    expect(api.get).toHaveBeenCalledTimes(2);
  });

  test('warns when a column indexed nothing', async () => {
    // The silent version of this is how someone ends up believing a field is
    // protected when every one of its values was too short to index.
    const user = userEvent.setup();
    api.get.mockResolvedValue({ data: [] });
    api.post.mockResolvedValue({
      data: set({ name: 'staff', columns: { name: 2 }, skippedColumns: ['dept', 'ref'], skippedValues: 4 }),
    });
    render(<ReferenceSets />);

    await user.click(await screen.findByRole('button', { name: /index first set/i }));
    await user.type(screen.getByLabelText(/set name/i), 'staff');
    await user.type(screen.getByLabelText(/records/i), 'name,ref\nSarah Okafor,CR-1');
    await user.click(screen.getByRole('button', { name: /^index set$/i }));

    expect(await screen.findByText(/matched nothing/i)).toBeInTheDocument();
    expect(screen.getByText('dept')).toBeInTheDocument();
    expect(screen.getByText('ref')).toBeInTheDocument();
    // The "not protected" sentence is deliberately split across elements to
    // emphasise the word "not", so match on the rendered text as a whole.
    expect(document.body.textContent).toMatch(/not\s*protected by this set/i);
  });

  test('no warning when every column indexed', async () => {
    const user = userEvent.setup();
    api.get.mockResolvedValue({ data: [] });
    api.post.mockResolvedValue({ data: set({ skippedColumns: [], skippedValues: 0 }) });
    render(<ReferenceSets />);

    await user.click(await screen.findByRole('button', { name: /index first set/i }));
    await user.type(screen.getByLabelText(/set name/i), 'customers');
    await user.type(screen.getByLabelText(/records/i), 'name,city\nSarah Okafor,Manchester');
    await user.click(screen.getByRole('button', { name: /^index set$/i }));

    await waitFor(() => expect(api.post).toHaveBeenCalled());
    expect(screen.queryByText(/matched nothing/i)).not.toBeInTheDocument();
  });

  test('a malformed CSV is reported without calling the API', async () => {
    const user = userEvent.setup();
    api.get.mockResolvedValue({ data: [] });
    render(<ReferenceSets />);

    await user.click(await screen.findByRole('button', { name: /index first set/i }));
    await user.type(screen.getByLabelText(/set name/i), 'broken');
    await user.type(screen.getByLabelText(/records/i), 'name,name\na,b');
    await user.click(screen.getByRole('button', { name: /^index set$/i }));

    expect(await screen.findByText(/unique/i)).toBeInTheDocument();
    expect(api.post).not.toHaveBeenCalled();
  });

  test("surfaces the backend's rejection reason", async () => {
    const user = userEvent.setup();
    api.get.mockResolvedValue({ data: [] });
    api.post.mockRejectedValue({
      response: { data: { error: 'min_fields is 5 but the rows have only 2 indexable column(s)' } },
    });
    render(<ReferenceSets />);

    await user.click(await screen.findByRole('button', { name: /index first set/i }));
    await user.type(screen.getByLabelText(/set name/i), 'bad');
    await user.type(screen.getByLabelText(/records/i), 'a,b\n1234,5678');
    await user.click(screen.getByRole('button', { name: /^index set$/i }));

    expect(await screen.findByText(/min_fields is 5/)).toBeInTheDocument();
  });

  test('deleting asks first, then calls the API', async () => {
    const user = userEvent.setup();
    api.get.mockResolvedValue({ data: [set()] });
    api.delete.mockResolvedValue({});
    render(<ReferenceSets />);

    await user.click(await screen.findByRole('button', { name: /delete customers/i }));
    expect(await screen.findByText(/every detection it provides stops/i)).toBeInTheDocument();
    expect(api.delete).not.toHaveBeenCalled();

    await user.click(screen.getByRole('button', { name: /^delete$/i }));
    await waitFor(() => expect(api.delete).toHaveBeenCalledWith('/api/edm/customers'));
  });

  test('tells the user their records are hashed, not stored', async () => {
    // Pasting real customer data into a form is a reasonable thing to
    // hesitate over; the page has to answer that before it is asked.
    const user = userEvent.setup();
    api.get.mockResolvedValue({ data: [] });
    render(<ReferenceSets />);

    await user.click(await screen.findByRole('button', { name: /index first set/i }));
    expect(screen.getByText(/hashed and discarded/i)).toBeInTheDocument();
  });
});
