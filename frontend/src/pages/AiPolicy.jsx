import { useEffect, useState } from 'react';
import { Brain, RefreshCw, ShieldX, ShieldCheck, Flag } from 'lucide-react';
import api from '../services/api.js';
import Modal from '../components/Modal.jsx';
import PageHeader from '../components/PageHeader.jsx';
import StatCard from '../components/StatCard.jsx';
import Badge from '../components/Badge.jsx';
import RiskBar from '../components/RiskBar.jsx';
import Spinner from '../components/Spinner.jsx';
import EmptyState from '../components/EmptyState.jsx';
import { formatDate, parseDetectionSample, PLATFORM_LABELS } from '../utils/format.js';

const PLATFORMS = Object.keys(PLATFORM_LABELS);

export default function AiPolicy() {
  const [attempts, setAttempts] = useState([]);
  const [total, setTotal]       = useState(0);
  const [loading, setLoading]   = useState(true);
  const [filter, setFilter]     = useState('');
  const [selected, setSelected] = useState(null);
  const [adminNoteDraft, setAdminNoteDraft] = useState('');
  const [updating, setUpdating] = useState(false);

  const load = async () => {
    setLoading(true);
    try {
      const { data } = await api.get('/api/ai-policy/attempts?limit=50');
      setAttempts(data.attempts ?? []);
      setTotal(data.total ?? 0);
    } catch (e) { console.error(e); }
    finally { setLoading(false); }
  };

  useEffect(() => { load(); }, []);

  const blocked   = attempts.filter(a => a.blocked).length;
  const displayed = filter ? attempts.filter(a => a.platform === filter) : attempts;

  const openDetail = (att) => {
    setSelected(att);
    setAdminNoteDraft(att.adminNote ?? '');
  };

  const saveAdminNote = async () => {
    if (!selected) return;
    setUpdating(true);
    try {
      const { data } = await api.patch(`/api/ai-policy/attempt/${selected.id}`, { adminNote: adminNoteDraft });
      setSelected((s) => ({ ...s, ...data }));
      setAttempts((prev) => prev.map((a) => (a.id === selected.id ? { ...a, ...data } : a)));
    } catch (e) { console.error(e); }
    finally { setUpdating(false); }
  };

  return (
    <div className="p-6 max-w-7xl mx-auto">
      <PageHeader title="AI Leak Policy" sub={`Generative AI data exfiltration attempts · ${total} detected`}>
        <button onClick={load} className="btn-secondary">
          <RefreshCw size={14} />
        </button>
      </PageHeader>

      <div className="grid grid-cols-3 gap-4 mb-5">
        <StatCard icon={Brain}       label="Total Attempts" value={total}           tone="accent" />
        <StatCard icon={ShieldX}     label="Blocked"        value={blocked}         tone="critical" />
        <StatCard icon={ShieldCheck} label="Allowed"        value={total - blocked} tone="medium" />
      </div>

      <div className="mb-4">
        <select className="select" value={filter} onChange={e => setFilter(e.target.value)}>
          <option value="">All Platforms</option>
          {PLATFORMS.map(p => <option key={p} value={p}>{PLATFORM_LABELS[p]}</option>)}
        </select>
      </div>

      <div className="card p-0 overflow-hidden">
        <table className="w-full text-left">
          <thead>
            <tr className="border-b border-border bg-surface-elevated/50">
              <th className="th">Platform</th>
              <th className="th">Method</th>
              <th className="th">Risk</th>
              <th className="th">Blocked</th>
              <th className="th">Agent</th>
              <th className="th">Policy</th>
              <th className="th">Content Sample</th>
              <th className="th">Time</th>
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr><td colSpan={8} className="text-center py-16"><Spinner /></td></tr>
            ) : displayed.length === 0 ? (
              <tr><td colSpan={8}><EmptyState icon={Brain} title="No AI leak attempts detected" /></td></tr>
            ) : displayed.map((att) => (
              <tr key={att.id} className="table-row" onClick={() => openDetail(att)}>
                <td className="td">
                  <span className="chip !text-[11px]">{PLATFORM_LABELS[att.platform] ?? att.platform}</span>
                </td>
                <td className="td text-xs text-ink-faint">{att.method}</td>
                <td className="td"><RiskBar score={att.riskScore} /></td>
                <td className="td">
                  <div className="flex items-center gap-1.5">
                    <Badge tone="blocked" value={att.blocked} label={att.blocked ? 'Blocked' : 'Allowed'} size="sm" />
                    {att.attempts > 1 && (
                      <span
                        title={`Blocked ${att.attempts} times in this window — a repeated attempt, not a one-off`}
                        className="chip !text-[10px] !px-1.5 !py-0 text-severity-critical-text"
                      >
                        ×{att.attempts}
                      </span>
                    )}
                    {att.reviewRequested && (
                      <span title="Worker flagged this for review" className="text-severity-medium-text">
                        <Flag size={12} />
                      </span>
                    )}
                  </div>
                </td>
                <td className="td font-mono text-xs text-ink-faint">{att.agent?.hostname ?? '—'}</td>
                <td className="td text-xs text-ink-faint truncate max-w-[140px]">{att.policy?.name ?? '—'}</td>
                <td className="td">
                  {(() => {
                    const d = parseDetectionSample(att.contentSample);
                    return (
                      <span className="flex items-center gap-1.5 max-w-[200px]">
                        {d.isEdm && (
                          <span
                            title={`Exact Data Match against the '${d.setName}' reference set — this is one of your own records, not content that merely looks sensitive`}
                            className="badge text-[9px] bg-accent-soft text-accent-text shrink-0"
                          >
                            EDM
                          </span>
                        )}
                        <span className="text-[11px] text-ink-faint font-mono truncate">
                          {att.contentSample ? d.text : '—'}
                        </span>
                      </span>
                    );
                  })()}
                </td>
                <td className="td text-xs text-ink-faint">{formatDate(att.timestamp)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <Modal open={!!selected} onClose={() => setSelected(null)} title="AI Leak Attempt Detail" maxWidth="max-w-xl">
        {selected && (
          <div className="space-y-4">
            <div className="flex items-center gap-2">
              <span className="chip">{PLATFORM_LABELS[selected.platform] ?? selected.platform}</span>
              <Badge tone="blocked" value={selected.blocked} label={selected.blocked ? 'Blocked' : 'Allowed'} />
            </div>

            <div className="grid grid-cols-2 gap-3 text-sm">
              {[
                ['Method',      selected.method],
                ['Risk Score',  selected.riskScore != null ? `${(selected.riskScore * 100).toFixed(0)}%` : '—'],
                ['Agent',       selected.agent?.hostname ?? '—'],
                ['Policy',      selected.policy?.name ?? '—'],
                ['Content Sample', selected.contentSample ?? '—'],
                ['Attempts',    selected.attempts > 1
                                  ? `${selected.attempts} (last ${formatDate(selected.lastAttemptAt)})`
                                  : '1'],
                ['Time',        formatDate(selected.timestamp)],
              ].map(([k, v]) => (
                <div key={k} className="bg-surface-elevated border border-border rounded-lg p-3">
                  <p className="text-[10px] font-semibold text-ink-faint uppercase tracking-wider mb-0.5">{k}</p>
                  <p className="text-ink text-xs break-all">{v}</p>
                </div>
              ))}
            </div>

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
          </div>
        )}
      </Modal>
    </div>
  );
}
