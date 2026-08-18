import { useEffect, useState, useCallback } from 'react';
import { Monitor, RefreshCw, Wifi, WifiOff, CheckCircle2, Circle, XCircle } from 'lucide-react';
import api from '../services/api.js';
import PageHeader from '../components/PageHeader.jsx';
import StatCard from '../components/StatCard.jsx';
import Badge from '../components/Badge.jsx';
import Spinner from '../components/Spinner.jsx';
import EmptyState from '../components/EmptyState.jsx';
import { formatDate, timeAgo } from '../utils/format.js';

function OnlineDot({ lastSeen }) {
  if (!lastSeen) return <span className="inline-block w-2 h-2 rounded-full bg-ink-faint/40" />;
  const mins = (Date.now() - new Date(lastSeen).getTime()) / 60000;
  const cls = mins < 5 ? 'bg-severity-low shadow-[0_0_6px_rgba(47,157,92,0.7)] animate-pulse'
            : mins < 60 ? 'bg-severity-medium'
            : 'bg-severity-critical';
  return <span className={`inline-block w-2 h-2 rounded-full ${cls}`} />;
}

export default function Agents() {
  const [agents, setAgents]   = useState([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter]   = useState('');

  const fetchAgents = useCallback(async () => {
    setLoading(true);
    try {
      const { data } = await api.get('/api/agents');
      setAgents(data);
    } catch (e) { console.error(e); }
    finally { setLoading(false); }
  }, []);

  useEffect(() => { fetchAgents(); }, [fetchAgents]);

  const active   = agents.filter(a => a.status === 'ACTIVE').length;
  const inactive = agents.filter(a => a.status !== 'ACTIVE').length;

  const displayed = filter
    ? agents.filter(a =>
        a.hostname.toLowerCase().includes(filter.toLowerCase()) ||
        a.os.toLowerCase().includes(filter.toLowerCase())
      )
    : agents;

  return (
    <div className="p-6 max-w-7xl mx-auto">
      <PageHeader title="Agents Fleet" sub={`${active} active · ${inactive} offline · ${agents.length} total`}>
        <button onClick={fetchAgents} className="btn-secondary">
          <RefreshCw size={14} /> Refresh
        </button>
      </PageHeader>

      <div className="grid grid-cols-3 gap-4 mb-5">
        <StatCard icon={CheckCircle2} label="Active"   value={active}         tone="low" />
        <StatCard icon={Circle}       label="Inactive" value={inactive}       tone="neutral" />
        <StatCard icon={Monitor}      label="Total"    value={agents.length}  tone="accent" />
      </div>

      <div className="mb-4">
        <input
          className="input max-w-xs"
          placeholder="Search by hostname or OS…"
          value={filter}
          onChange={e => setFilter(e.target.value)}
        />
      </div>

      <div className="card p-0 overflow-hidden">
        <table className="w-full text-left">
          <thead>
            <tr className="border-b border-border bg-surface-elevated/50">
              <th className="th">Status</th>
              <th className="th">Hostname</th>
              <th className="th">OS</th>
              <th className="th">Version</th>
              <th className="th">Last Seen</th>
              <th className="th">Enrolled</th>
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr><td colSpan={6} className="text-center py-16"><Spinner /></td></tr>
            ) : displayed.length === 0 ? (
              <tr><td colSpan={6}>
                <EmptyState icon={filter ? XCircle : Monitor}
                  title={filter ? 'No agents match your search' : 'No agents enrolled'} />
              </td></tr>
            ) : displayed.map((agent) => (
              <tr key={agent.id} className="table-row cursor-default">
                <td className="td">
                  <div className="flex items-center gap-2">
                    <OnlineDot lastSeen={agent.lastSeen} />
                    <Badge tone="agentStatus" value={agent.status} size="sm" />
                  </div>
                </td>
                <td className="td font-mono text-ink text-xs">{agent.hostname}</td>
                <td className="td text-ink-faint text-xs">{agent.os}</td>
                <td className="td"><span className="chip !py-0.5 !text-[11px]">v{agent.version}</span></td>
                <td className="td">
                  <div className="flex items-center gap-1.5">
                    {agent.lastSeen
                      ? <><Wifi size={12} className="text-ink-faint" /><span className="text-xs text-ink-faint">{timeAgo(agent.lastSeen)}</span></>
                      : <><WifiOff size={12} className="text-ink-faint/50" /><span className="text-xs text-ink-faint/50">Never</span></>
                    }
                  </div>
                </td>
                <td className="td text-xs text-ink-faint">{formatDate(agent.createdAt)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
