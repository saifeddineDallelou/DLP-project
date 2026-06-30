import { useEffect, useState, useCallback } from 'react';
import {
  Filter, File, Clipboard, Usb, Printer, Camera, Network, RefreshCw,
} from 'lucide-react';
import api from '../services/api.js';
import Modal from '../components/Modal.jsx';
import { formatDate, SEVERITY_STYLES, STATUS_STYLES } from '../utils/format.js';

const CHANNEL_ICON = {
  FILE: File, CLIPBOARD: Clipboard, USB: Usb,
  PRINT: Printer, SCREENSHOT: Camera, NETWORK: Network,
};

const SEVERITIES = ['', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
const STATUSES   = ['', 'OPEN', 'IN_PROGRESS', 'RESOLVED', 'FALSE_POSITIVE'];

function RiskBar({ score }) {
  if (score == null) return <span className="text-slate-600">—</span>;
  const pct = Math.round(score * 100);
  const color = pct >= 70 ? 'bg-red-500' : pct >= 40 ? 'bg-amber-500' : 'bg-emerald-500';
  return (
    <div className="flex items-center gap-2">
      <div className="w-16 h-1.5 bg-slate-700 rounded-full overflow-hidden">
        <div className={`h-full rounded-full ${color}`} style={{ width: `${pct}%` }} />
      </div>
      <span className="text-xs text-slate-400">{pct}%</span>
    </div>
  );
}

export default function Incidents() {
  const [incidents, setIncidents] = useState([]);
  const [total, setTotal]         = useState(0);
  const [page, setPage]           = useState(1);
  const [filterStatus,   setFilterStatus]   = useState('');
  const [filterSeverity, setFilterSeverity] = useState('');
  const [selected, setSelected]   = useState(null);
  const [loading, setLoading]     = useState(true);
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

  return (
    <div className="p-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-xl font-bold text-slate-100">Incidents</h1>
          <p className="text-sm text-slate-400 mt-0.5">{total} total incidents</p>
        </div>
        <button onClick={fetchIncidents} className="btn-secondary flex items-center gap-2 text-sm">
          <RefreshCw size={14} /> Refresh
        </button>
      </div>

      {/* Filters */}
      <div className="card mb-4 flex items-center gap-3">
        <Filter size={14} className="text-slate-500" />
        <select
          className="select"
          value={filterStatus}
          onChange={e => { setFilterStatus(e.target.value); setPage(1); }}
        >
          <option value="">All Statuses</option>
          {STATUSES.filter(Boolean).map(s => (
            <option key={s} value={s}>{s.replace('_', ' ')}</option>
          ))}
        </select>
        <select
          className="select"
          value={filterSeverity}
          onChange={e => { setFilterSeverity(e.target.value); setPage(1); }}
        >
          <option value="">All Severities</option>
          {SEVERITIES.filter(Boolean).map(s => (
            <option key={s} value={s}>{s}</option>
          ))}
        </select>
        {(filterStatus || filterSeverity) && (
          <button
            onClick={() => { setFilterStatus(''); setFilterSeverity(''); setPage(1); }}
            className="text-xs text-slate-500 hover:text-slate-300 transition-colors"
          >
            Clear
          </button>
        )}
      </div>

      {/* Table */}
      <div className="card p-0 overflow-hidden">
        <table className="w-full text-left">
          <thead>
            <tr className="border-b border-slate-800 bg-slate-900/50">
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
              <tr><td colSpan={7} className="text-center py-16">
                <div className="inline-block w-6 h-6 border-2 border-indigo-500 border-t-transparent
                                rounded-full animate-spin" />
              </td></tr>
            ) : incidents.length === 0 ? (
              <tr><td colSpan={7} className="text-center py-16 text-slate-500 text-sm">
                No incidents found
              </td></tr>
            ) : incidents.map((inc) => {
              const ChanIcon = CHANNEL_ICON[inc.channel] ?? File;
              return (
                <tr
                  key={inc.id}
                  className="table-row"
                  onClick={() => setSelected(inc)}
                >
                  <td className="td">
                    <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-semibold
                                     border ${SEVERITY_STYLES[inc.severity]}`}>
                      {inc.severity}
                    </span>
                  </td>
                  <td className="td">
                    <div className="flex items-center gap-1.5 text-slate-400">
                      <ChanIcon size={13} />
                      <span className="text-xs">{inc.channel}</span>
                    </div>
                  </td>
                  <td className="td">
                    <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium
                                     border ${STATUS_STYLES[inc.status]}`}>
                      {inc.status.replace(/_/g, ' ')}
                    </span>
                  </td>
                  <td className="td"><RiskBar score={inc.riskScore} /></td>
                  <td className="td font-mono text-xs text-slate-400">{inc.agent?.hostname ?? '—'}</td>
                  <td className="td text-xs text-slate-400 truncate max-w-[140px]">
                    {inc.policy?.name ?? '—'}
                  </td>
                  <td className="td text-xs text-slate-500">{formatDate(inc.createdAt)}</td>
                </tr>
              );
            })}
          </tbody>
        </table>

        {/* Pagination */}
        {totalPages > 1 && (
          <div className="flex items-center justify-between px-4 py-3 border-t border-slate-800">
            <span className="text-xs text-slate-500">
              Page {page} of {totalPages}
            </span>
            <div className="flex gap-2">
              <button
                className="btn-secondary text-xs px-3 py-1.5"
                disabled={page === 1}
                onClick={() => setPage(p => p - 1)}
              >← Prev</button>
              <button
                className="btn-secondary text-xs px-3 py-1.5"
                disabled={page === totalPages}
                onClick={() => setPage(p => p + 1)}
              >Next →</button>
            </div>
          </div>
        )}
      </div>

      {/* Detail Modal */}
      <Modal open={!!selected} onClose={() => setSelected(null)} title="Incident Detail" maxWidth="max-w-xl">
        {selected && (
          <div className="space-y-4 text-sm">
            <div className="grid grid-cols-2 gap-3">
              {[
                ['ID',       selected.id?.slice(0, 8) + '…'],
                ['Channel',  selected.channel],
                ['Severity', selected.severity],
                ['Status',   selected.status?.replace(/_/g, ' ')],
                ['Risk Score', selected.riskScore != null ? `${(selected.riskScore*100).toFixed(0)}%` : '—'],
                ['Agent',    selected.agent?.hostname ?? '—'],
                ['OS',       selected.agent?.os ?? '—'],
                ['Policy',   selected.policy?.name ?? '—'],
                ['Action',   selected.policy?.action ?? '—'],
                ['Assigned', selected.assignedTo?.email ?? 'Unassigned'],
                ['Created',  formatDate(selected.createdAt)],
                ['Updated',  formatDate(selected.updatedAt)],
              ].map(([k, v]) => (
                <div key={k} className="bg-slate-800 rounded-lg p-3">
                  <p className="text-[10px] font-semibold text-slate-500 uppercase tracking-wider mb-0.5">{k}</p>
                  <p className="text-slate-200 font-mono text-xs break-all">{v}</p>
                </div>
              ))}
            </div>
            {selected.resolvedAt && (
              <div className="bg-emerald-500/10 border border-emerald-500/20 rounded-lg p-3">
                <p className="text-xs text-emerald-400">
                  Resolved at {formatDate(selected.resolvedAt)}
                </p>
              </div>
            )}
          </div>
        )}
      </Modal>
    </div>
  );
}
