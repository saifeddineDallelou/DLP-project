import { useEffect, useState, useCallback } from 'react';
import { Monitor, RefreshCw, Wifi, WifiOff } from 'lucide-react';
import api from '../services/api.js';
import { formatDate, timeAgo } from '../utils/format.js';

const STATUS_BADGE = {
  ACTIVE:   'text-emerald-400 bg-emerald-500/10 border-emerald-500/20',
  INACTIVE: 'text-slate-400   bg-slate-500/10   border-slate-500/20',
  ERROR:    'text-red-400     bg-red-500/10     border-red-500/20',
};

function OnlineDot({ lastSeen }) {
  if (!lastSeen) return <span className="inline-block w-2 h-2 rounded-full bg-slate-700" />;
  const diff = Date.now() - new Date(lastSeen).getTime();
  const mins = diff / 60000;
  const color = mins < 5 ? 'bg-emerald-400 shadow-emerald-400/50 shadow-sm animate-pulse'
               : mins < 60 ? 'bg-amber-400'
               : 'bg-red-500';
  return <span className={`inline-block w-2 h-2 rounded-full ${color}`} />;
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
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-xl font-bold text-slate-100">Agents Fleet</h1>
          <p className="text-sm text-slate-400 mt-0.5">
            {active} active · {inactive} offline · {agents.length} total
          </p>
        </div>
        <button onClick={fetchAgents} className="btn-secondary flex items-center gap-2 text-sm">
          <RefreshCw size={14} /> Refresh
        </button>
      </div>

      {/* Summary cards */}
      <div className="grid grid-cols-3 gap-4 mb-5">
        {[
          { label: 'Active',   count: active,            color: 'text-emerald-400', bg: 'bg-emerald-500/10' },
          { label: 'Inactive', count: inactive,           color: 'text-slate-400',   bg: 'bg-slate-500/10'   },
          { label: 'Total',    count: agents.length,     color: 'text-indigo-400',  bg: 'bg-indigo-500/10'  },
        ].map(({ label, count, color, bg }) => (
          <div key={label} className="card flex items-center gap-3">
            <div className={`w-9 h-9 rounded-lg ${bg} flex items-center justify-center`}>
              <Monitor size={16} className={color} />
            </div>
            <div>
              <p className="text-xs text-slate-500">{label}</p>
              <p className={`text-xl font-bold ${color}`}>{count}</p>
            </div>
          </div>
        ))}
      </div>

      {/* Search */}
      <div className="mb-4">
        <input
          className="input max-w-xs"
          placeholder="Search by hostname or OS…"
          value={filter}
          onChange={e => setFilter(e.target.value)}
        />
      </div>

      {/* Table */}
      <div className="card p-0 overflow-hidden">
        <table className="w-full text-left">
          <thead>
            <tr className="border-b border-slate-800 bg-slate-900/50">
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
              <tr><td colSpan={6} className="text-center py-16">
                <div className="inline-block w-6 h-6 border-2 border-indigo-500 border-t-transparent
                                rounded-full animate-spin" />
              </td></tr>
            ) : displayed.length === 0 ? (
              <tr><td colSpan={6} className="text-center py-16 text-slate-500 text-sm">
                {filter ? 'No agents match your search' : 'No agents enrolled'}
              </td></tr>
            ) : displayed.map((agent) => (
              <tr key={agent.id} className="table-row cursor-default">
                <td className="td">
                  <div className="flex items-center gap-2">
                    <OnlineDot lastSeen={agent.lastSeen} />
                    <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs
                                     font-medium border ${STATUS_BADGE[agent.status]}`}>
                      {agent.status}
                    </span>
                  </div>
                </td>
                <td className="td font-mono text-slate-200 text-xs">{agent.hostname}</td>
                <td className="td text-slate-400 text-xs">{agent.os}</td>
                <td className="td">
                  <span className="text-xs bg-slate-800 text-slate-400 px-2 py-0.5 rounded font-mono">
                    v{agent.version}
                  </span>
                </td>
                <td className="td">
                  <div className="flex items-center gap-1.5">
                    {agent.lastSeen
                      ? <><Wifi size={12} className="text-slate-500" /><span className="text-xs text-slate-400">{timeAgo(agent.lastSeen)}</span></>
                      : <><WifiOff size={12} className="text-slate-600" /><span className="text-xs text-slate-600">Never</span></>
                    }
                  </div>
                </td>
                <td className="td text-xs text-slate-500">{formatDate(agent.createdAt)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
