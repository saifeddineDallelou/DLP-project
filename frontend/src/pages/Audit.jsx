import { useEffect, useState, useCallback } from 'react';
import { ScrollText, RefreshCw, ChevronLeft, ChevronRight, X } from 'lucide-react';
import api from '../services/api.js';
import PageHeader from '../components/PageHeader.jsx';
import EmptyState from '../components/EmptyState.jsx';
import Spinner from '../components/Spinner.jsx';
import Modal from '../components/Modal.jsx';
import { formatDate } from '../utils/format.js';

const EMPTY_FILTERS = { resource: '', action: '', from: '', to: '' };
const PAGE_SIZE = 25;

// Read-only by design: there is no create/edit/delete here, because audit rows
// are only ever written as a side effect of the action they record. A trail an
// operator can edit is not evidence of anything.
export default function Audit() {
  const [logs, setLogs]       = useState([]);
  const [total, setTotal]     = useState(0);
  const [pages, setPages]     = useState(1);
  const [page, setPage]       = useState(1);
  const [loading, setLoading] = useState(true);
  const [filters, setFilters] = useState(EMPTY_FILTERS);
  // Populated from the rows that actually exist, so the dropdowns never drift
  // out of sync with newly audited actions.
  const [options, setOptions] = useState({ actions: [], resources: [] });
  const [detail, setDetail]   = useState(null);

  const fetchLogs = useCallback(async () => {
    setLoading(true);
    try {
      const params = new URLSearchParams({ page: String(page), limit: String(PAGE_SIZE) });
      Object.entries(filters).forEach(([k, v]) => { if (v) params.set(k, v); });

      const { data } = await api.get(`/api/audit?${params}`);
      setLogs(data.logs);
      setTotal(data.total);
      setPages(data.pages || 1);
    } catch (e) { console.error(e); }
    finally { setLoading(false); }
  }, [page, filters]);

  useEffect(() => { fetchLogs(); }, [fetchLogs]);

  useEffect(() => {
    api.get('/api/audit/actions')
      .then(({ data }) => setOptions(data))
      .catch((e) => console.error(e));
  }, []);

  const setFilter = (key, value) => {
    setPage(1);              // a filter change invalidates the current page
    setFilters((f) => ({ ...f, [key]: value }));
  };

  const clearFilters = () => { setPage(1); setFilters(EMPTY_FILTERS); };
  const hasFilters = Object.values(filters).some(Boolean);

  return (
    <div>
      <PageHeader
        title="Audit Trail"
        sub="Every privileged action taken in the console, newest first"
      >
        <button
          onClick={fetchLogs}
          className="flex items-center gap-2 px-3 py-2 rounded-lg text-xs font-medium
                     text-ink-soft hover:text-ink hover:bg-surface-hover transition-colors"
        >
          <RefreshCw size={14} />
          Refresh
        </button>
      </PageHeader>

      {/* Filters */}
      <div className="flex flex-wrap items-end gap-3 mb-5">
        <label className="flex flex-col gap-1">
          <span className="text-[10px] font-semibold text-ink-faint uppercase tracking-wider">Resource</span>
          <select
            value={filters.resource}
            onChange={(e) => setFilter('resource', e.target.value)}
            className="bg-surface-raised border border-border rounded-lg px-3 py-2 text-sm text-ink min-w-[10rem]"
          >
            <option value="">All resources</option>
            {options.resources.map((r) => <option key={r} value={r}>{r}</option>)}
          </select>
        </label>

        <label className="flex flex-col gap-1">
          <span className="text-[10px] font-semibold text-ink-faint uppercase tracking-wider">Action</span>
          <select
            value={filters.action}
            onChange={(e) => setFilter('action', e.target.value)}
            className="bg-surface-raised border border-border rounded-lg px-3 py-2 text-sm text-ink min-w-[14rem]"
          >
            <option value="">All actions</option>
            {options.actions.map((a) => <option key={a} value={a}>{a}</option>)}
          </select>
        </label>

        <label className="flex flex-col gap-1">
          <span className="text-[10px] font-semibold text-ink-faint uppercase tracking-wider">From</span>
          <input
            type="date"
            value={filters.from}
            onChange={(e) => setFilter('from', e.target.value)}
            className="bg-surface-raised border border-border rounded-lg px-3 py-2 text-sm text-ink"
          />
        </label>

        <label className="flex flex-col gap-1">
          <span className="text-[10px] font-semibold text-ink-faint uppercase tracking-wider">To</span>
          <input
            type="date"
            value={filters.to}
            onChange={(e) => setFilter('to', e.target.value)}
            className="bg-surface-raised border border-border rounded-lg px-3 py-2 text-sm text-ink"
          />
        </label>

        {hasFilters && (
          <button
            onClick={clearFilters}
            className="flex items-center gap-1.5 px-3 py-2 rounded-lg text-xs font-medium
                       text-ink-soft hover:text-ink hover:bg-surface-hover transition-colors"
          >
            <X size={13} />
            Clear
          </button>
        )}
      </div>

      {loading ? (
        <Spinner />
      ) : logs.length === 0 ? (
        <EmptyState
          icon={ScrollText}
          title={hasFilters ? 'No entries match these filters' : 'No audit entries yet'}
          sub={
            hasFilters
              ? 'Try widening the date range or clearing a filter.'
              : 'Privileged actions — policy edits, adjudications, baseline changes, agent deletion — are recorded here as they happen.'
          }
        />
      ) : (
        <>
          <div className="rounded-xl border border-border overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="bg-surface-raised text-left">
                    <th className="px-4 py-3 text-[10px] font-semibold text-ink-faint uppercase tracking-wider">When</th>
                    <th className="px-4 py-3 text-[10px] font-semibold text-ink-faint uppercase tracking-wider">Who</th>
                    <th className="px-4 py-3 text-[10px] font-semibold text-ink-faint uppercase tracking-wider">Action</th>
                    <th className="px-4 py-3 text-[10px] font-semibold text-ink-faint uppercase tracking-wider">Resource</th>
                    <th className="px-4 py-3 text-[10px] font-semibold text-ink-faint uppercase tracking-wider">IP</th>
                    <th className="px-4 py-3" />
                  </tr>
                </thead>
                <tbody className="divide-y divide-border">
                  {logs.map((log) => (
                    <tr key={log.id} className="hover:bg-surface-hover transition-colors">
                      <td className="px-4 py-3 text-ink-soft whitespace-nowrap">{formatDate(log.createdAt)}</td>
                      <td className="px-4 py-3">
                        {log.user ? (
                          <div>
                            <div className="text-ink">{log.user.email}</div>
                            <div className="text-[10px] text-ink-faint">{log.user.role}</div>
                          </div>
                        ) : (
                          // The FK is nullable, so a row survives the deletion
                          // of the account that created it. Losing the actor is
                          // better than losing the record of the action.
                          <span className="text-ink-faint italic">deleted user</span>
                        )}
                      </td>
                      <td className="px-4 py-3">
                        <code className="text-xs text-accent-text">{log.action}</code>
                      </td>
                      <td className="px-4 py-3 text-ink-soft">
                        <div>{log.resource}</div>
                        {log.resourceId && (
                          <div className="text-[10px] text-ink-faint font-mono truncate max-w-[12rem]">
                            {log.resourceId}
                          </div>
                        )}
                      </td>
                      <td className="px-4 py-3 text-ink-faint font-mono text-xs">{log.ipAddress ?? '—'}</td>
                      <td className="px-4 py-3 text-right">
                        {log.metadata && Object.keys(log.metadata).length > 0 && (
                          <button
                            onClick={() => setDetail(log)}
                            className="text-xs text-ink-soft hover:text-ink underline underline-offset-2"
                          >
                            Details
                          </button>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          <div className="flex items-center justify-between mt-4">
            <p className="text-xs text-ink-faint">
              {total} {total === 1 ? 'entry' : 'entries'} · page {page} of {pages}
            </p>
            <div className="flex items-center gap-1">
              <button
                onClick={() => setPage((p) => Math.max(1, p - 1))}
                disabled={page <= 1}
                className="p-2 rounded-lg text-ink-soft hover:text-ink hover:bg-surface-hover
                           disabled:opacity-30 disabled:pointer-events-none transition-colors"
              >
                <ChevronLeft size={16} />
              </button>
              <button
                onClick={() => setPage((p) => Math.min(pages, p + 1))}
                disabled={page >= pages}
                className="p-2 rounded-lg text-ink-soft hover:text-ink hover:bg-surface-hover
                           disabled:opacity-30 disabled:pointer-events-none transition-colors"
              >
                <ChevronRight size={16} />
              </button>
            </div>
          </div>
        </>
      )}

      <Modal
        open={!!detail}
        onClose={() => setDetail(null)}
        title={detail?.action ?? 'Entry detail'}
      >
        {detail && (
          <div className="space-y-3 text-sm">
            <div className="grid grid-cols-2 gap-3">
              <Field label="When" value={formatDate(detail.createdAt)} />
              <Field label="Who" value={detail.user?.email ?? 'deleted user'} />
              <Field label="Resource" value={detail.resource} />
              <Field label="Resource ID" value={detail.resourceId ?? '—'} mono />
              <Field label="IP address" value={detail.ipAddress ?? '—'} mono />
            </div>
            <div>
              <p className="text-[10px] font-semibold text-ink-faint uppercase tracking-wider mb-1.5">
                Recorded detail
              </p>
              <pre className="bg-surface-raised border border-border rounded-lg p-3 text-xs
                              text-ink-soft overflow-x-auto">
                {JSON.stringify(detail.metadata, null, 2)}
              </pre>
            </div>
          </div>
        )}
      </Modal>
    </div>
  );
}

function Field({ label, value, mono }) {
  return (
    <div>
      <p className="text-[10px] font-semibold text-ink-faint uppercase tracking-wider mb-1">{label}</p>
      <p className={`text-ink-soft break-all ${mono ? 'font-mono text-xs' : ''}`}>{value}</p>
    </div>
  );
}
