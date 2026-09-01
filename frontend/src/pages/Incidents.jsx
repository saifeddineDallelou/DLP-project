import { useEffect, useState, useCallback } from 'react';
import { Filter, RefreshCw, PlayCircle, CheckCircle2, XCircle, RotateCcw, Flag } from 'lucide-react';
import api from '../services/api.js';
import Modal from '../components/Modal.jsx';
import Badge from '../components/Badge.jsx';
import RiskBar from '../components/RiskBar.jsx';
import PageHeader from '../components/PageHeader.jsx';
import Spinner from '../components/Spinner.jsx';
import EmptyState from '../components/EmptyState.jsx';
import { useAuth } from '../context/AuthContext.jsx';
import { formatDate, CHANNEL_ICON } from '../utils/format.js';
import { File } from 'lucide-react';

const SEVERITIES = ['', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
const STATUSES   = ['', 'OPEN', 'IN_PROGRESS', 'RESOLVED', 'FALSE_POSITIVE'];

export default function Incidents() {
  const { user } = useAuth();
  const [incidents, setIncidents] = useState([]);
  const [total, setTotal]         = useState(0);
  const [page, setPage]           = useState(1);
  const [filterStatus,   setFilterStatus]   = useState('');
  const [filterSeverity, setFilterSeverity] = useState('');
  const [selected, setSelected]   = useState(null);
  const [loading, setLoading]     = useState(true);
  const [updating, setUpdating]   = useState(false);
  const [adminNoteDraft, setAdminNoteDraft] = useState('');
  const LIMIT = 15;

  const fetchIncidents = useCallback(async () => {
    setLoading(true);
    try {
      const params = new URLSearchParams({ page, limit: LIMIT });
      if (filterStatus)   params.set('status',   filterStatus);
      if (filterSeverity) params.set('severity', filterSeverity);
      const { data } = await api.get(`/api/incidents?${params}`);
      setIncidents(data.incidents ?? []);
      setTotal(data.total ?? 0);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  }, [page, filterStatus, filterSeverity]);

  useEffect(() => { fetchIncidents(); }, [fetchIncidents]);

  const totalPages = Math.ceil(total / LIMIT);

  const setStatus = async (status, extra = {}) => {
    if (!selected) return;
    setUpdating(true);
    try {
      const { data } = await api.patch(`/api/incidents/${selected.id}`, { status, ...extra });
      setSelected((s) => ({ ...s, ...data }));
      fetchIncidents();
    } catch (e) {
      console.error(e);
    } finally {
      setUpdating(false);
    }
  };

  const saveAdminNote = async () => {
    if (!selected) return;
    setUpdating(true);
    try {
      const { data } = await api.patch(`/api/incidents/${selected.id}`, { adminNote: adminNoteDraft });
      setSelected((s) => ({ ...s, ...data }));
      fetchIncidents();
    } catch (e) {
      console.error(e);
    } finally {
      setUpdating(false);
    }
  };

  return (
    <div className="p-6 max-w-7xl mx-auto">
      <PageHeader title="Incidents" sub={`${total} total incidents`}>
        <button onClick={fetchIncidents} className="btn-secondary">
          <RefreshCw size={14} /> Refresh
        </button>
      </PageHeader>

      {/* Filters */}
      <div className="card mb-4 flex items-center gap-3 py-3.5">
        <Filter size={14} className="text-ink-faint" />
        <select className="select" value={filterStatus}
          onChange={e => { setFilterStatus(e.target.value); setPage(1); }}>
          <option value="">All Statuses</option>
          {STATUSES.filter(Boolean).map(s => <option key={s} value={s}>{s.replace('_', ' ')}</option>)}
        </select>
        <select className="select" value={filterSeverity}
          onChange={e => { setFilterSeverity(e.target.value); setPage(1); }}>
          <option value="">All Severities</option>
          {SEVERITIES.filter(Boolean).map(s => <option key={s} value={s}>{s}</option>)}
        </select>
        {(filterStatus || filterSeverity) && (
          <button
            onClick={() => { setFilterStatus(''); setFilterSeverity(''); setPage(1); }}
            className="text-xs text-ink-faint hover:text-ink transition-colors"
          >
            Clear
          </button>
        )}
      </div>

      {/* Table */}
      <div className="card p-0 overflow-hidden">
        <table className="w-full text-left">
          <thead>
            <tr className="border-b border-border bg-surface-elevated/50">
              <th className="th">Severity</th>
              <th className="th">Channel</th>
              <th className="th">Status</th>
              <th className="th">Risk</th>
              <th className="th">Agent</th>
              <th className="th">Policy</th>
              <th className="th">Created</th>
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr><td colSpan={7} className="text-center py-16"><Spinner /></td></tr>
            ) : incidents.length === 0 ? (
              <tr><td colSpan={7}><EmptyState title="No incidents found" /></td></tr>
            ) : incidents.map((inc) => {
              const ChanIcon = CHANNEL_ICON[inc.channel] ?? File;
              return (
                <tr key={inc.id} className="table-row" onClick={() => { setSelected(inc); setAdminNoteDraft(inc.adminNote ?? ''); }}>
                  <td className="td"><Badge tone="severity" value={inc.severity} size="sm" /></td>
                  <td className="td">
                    <div className="flex items-center gap-1.5 text-ink-faint">
                      <ChanIcon size={13} />
                      <span className="text-xs">{inc.channel}</span>
                    </div>
                  </td>
                  <td className="td">
                    <div className="flex items-center gap-1.5">
                      <Badge tone="status" value={inc.status} size="sm" />
                      {inc.reviewRequested && (
                        <span title="Worker flagged this for review" className="text-severity-medium-text">
                          <Flag size={12} />
                        </span>
                      )}
                    </div>
                  </td>
                  <td className="td"><RiskBar score={inc.riskScore} /></td>
                  <td className="td font-mono text-xs text-ink-faint">{inc.agent?.hostname ?? '—'}</td>
                  <td className="td text-xs text-ink-faint truncate max-w-[140px]">{inc.policy?.name ?? '—'}</td>
                  <td className="td text-xs text-ink-faint">{formatDate(inc.createdAt)}</td>
                </tr>
              );
            })}
          </tbody>
        </table>

        {totalPages > 1 && (
          <div className="flex items-center justify-between px-4 py-3 border-t border-border">
            <span className="text-xs text-ink-faint">Page {page} of {totalPages}</span>
            <div className="flex gap-2">
              <button className="btn-secondary text-xs px-3 py-1.5" disabled={page === 1}
                onClick={() => setPage(p => p - 1)}>← Prev</button>
              <button className="btn-secondary text-xs px-3 py-1.5" disabled={page === totalPages}
                onClick={() => setPage(p => p + 1)}>Next →</button>
            </div>
          </div>
        )}
      </div>

      {/* Detail Modal */}
      <Modal open={!!selected} onClose={() => setSelected(null)} title="Incident Detail" maxWidth="max-w-xl">
        {selected && (
          <div className="space-y-4">
            <div className="flex items-center gap-2">
              <Badge tone="severity" value={selected.severity} />
              <Badge tone="status" value={selected.status} />
            </div>

            <div className="grid grid-cols-2 gap-3 text-sm">
              {[
                ['Channel',    selected.channel],
                ['Risk Score', selected.riskScore != null ? `${(selected.riskScore*100).toFixed(0)}%` : '—'],
                ['Agent',      selected.agent?.hostname ?? '—'],
                ['OS',         selected.agent?.os ?? '—'],
                ['Policy',     selected.policy?.name ?? '—'],
                ['Action',     selected.policy?.action ?? '—'],
                ['Assigned',   selected.assignedTo?.email ?? 'Unassigned'],
                ['Created',    formatDate(selected.createdAt)],
              ].map(([k, v]) => (
                <div key={k} className="bg-surface-elevated border border-border rounded-lg p-3">
                  <p className="text-[10px] font-semibold text-ink-faint uppercase tracking-wider mb-0.5">{k}</p>
                  <p className="text-ink text-xs break-all">{v}</p>
                </div>
              ))}
            </div>

            {selected.resolvedAt && (
              <div className="bg-severity-low-soft border border-severity-low/25 rounded-lg p-3">
                <p className="text-xs text-severity-low-text">Resolved at {formatDate(selected.resolvedAt)}</p>
              </div>
            )}

            {selected.reviewRequested && (
              <div className="bg-severity-medium-soft border border-severity-medium/25 rounded-lg p-3">
                <p className="text-[10px] font-semibold text-severity-medium-text uppercase tracking-wider mb-1 flex items-center gap-1">
                  <Flag size={11} /> Worker flagged this for review
                </p>
                <p className="text-xs text-ink break-words">
                  {selected.justification || <span className="text-ink-faint italic">No note left</span>}
                </p>
              </div>
            )}

            {/* Admin explanation -- the admin's own disposition after
                investigating, separate from the worker's note above */}
            <div>
              <p className="label mb-1.5">Admin note</p>
              <textarea
                className="input w-full text-xs resize-none"
                rows={3}
                placeholder="Record what you found and the disposition..."
                value={adminNoteDraft}
                onChange={(e) => setAdminNoteDraft(e.target.value)}
              />
              <button
                className="btn-secondary text-xs mt-2"
                disabled={updating || adminNoteDraft === (selected.adminNote ?? '')}
                onClick={saveAdminNote}
              >
                Save note
              </button>
            </div>

            {/* Triage actions */}
            <div className="border-t border-border pt-4">
              <p className="label mb-2">Triage</p>
              <div className="flex flex-wrap gap-2">
                {selected.status === 'OPEN' && (
                  <button
                    className="btn-secondary text-xs"
                    disabled={updating}
                    onClick={() => setStatus('IN_PROGRESS', { assignedToId: user?.id })}
                  >
                    <PlayCircle size={13} /> Start investigating
                  </button>
                )}
                {(selected.status === 'OPEN' || selected.status === 'IN_PROGRESS') && (
                  <>
                    <button
                      className="btn-secondary text-xs !text-severity-low-text !bg-severity-low-soft !border-severity-low/25"
                      disabled={updating}
                      onClick={() => setStatus('RESOLVED', { assignedToId: user?.id })}
                    >
                      <CheckCircle2 size={13} /> Resolve
                    </button>
                    <button
                      className="btn-secondary text-xs"
                      disabled={updating}
                      onClick={() => setStatus('FALSE_POSITIVE', { assignedToId: user?.id })}
                    >
                      <XCircle size={13} /> False positive
                    </button>
                  </>
                )}
                {(selected.status === 'RESOLVED' || selected.status === 'FALSE_POSITIVE') && (
                  <button className="btn-ghost text-xs" disabled={updating} onClick={() => setStatus('OPEN')}>
                    <RotateCcw size={13} /> Reopen
                  </button>
                )}
              </div>
            </div>
          </div>
        )}
      </Modal>
    </div>
  );
}
