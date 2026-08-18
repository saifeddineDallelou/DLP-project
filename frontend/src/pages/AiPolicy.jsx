import { useEffect, useState } from 'react';
import { Brain, RefreshCw, ShieldX, ShieldCheck } from 'lucide-react';
import api from '../services/api.js';
import PageHeader from '../components/PageHeader.jsx';
import StatCard from '../components/StatCard.jsx';
import Badge from '../components/Badge.jsx';
import RiskBar from '../components/RiskBar.jsx';
import Spinner from '../components/Spinner.jsx';
import EmptyState from '../components/EmptyState.jsx';
import { formatDate, PLATFORM_LABELS } from '../utils/format.js';

const PLATFORMS = Object.keys(PLATFORM_LABELS);

export default function AiPolicy() {
  const [attempts, setAttempts] = useState([]);
  const [total, setTotal]       = useState(0);
  const [loading, setLoading]   = useState(true);
  const [filter, setFilter]     = useState('');

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
              <th className="th">Content Sample</th>
              <th className="th">Time</th>
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr><td colSpan={7} className="text-center py-16"><Spinner /></td></tr>
            ) : displayed.length === 0 ? (
              <tr><td colSpan={7}><EmptyState icon={Brain} title="No AI leak attempts detected" /></td></tr>
            ) : displayed.map((att) => (
              <tr key={att.id} className="table-row cursor-default">
                <td className="td">
                  <span className="chip !text-[11px]">{PLATFORM_LABELS[att.platform] ?? att.platform}</span>
                </td>
                <td className="td text-xs text-ink-faint">{att.method}</td>
                <td className="td"><RiskBar score={att.riskScore} /></td>
                <td className="td"><Badge tone="blocked" value={att.blocked} label={att.blocked ? 'Blocked' : 'Allowed'} size="sm" /></td>
                <td className="td font-mono text-xs text-ink-faint">{att.agent?.hostname ?? '—'}</td>
                <td className="td">
                  <span className="text-[11px] text-ink-faint font-mono max-w-[180px] block truncate">
                    {att.contentSample ?? '—'}
                  </span>
                </td>
                <td className="td text-xs text-ink-faint">{formatDate(att.timestamp)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
