import { useEffect, useState } from 'react';
import { Brain, RefreshCw, ShieldX, ShieldCheck } from 'lucide-react';
import api from '../services/api.js';
import { formatDate } from '../utils/format.js';

const PLATFORM_COLORS = {
  CHATGPT: 'text-emerald-400 bg-emerald-500/10',
  CLAUDE:  'text-violet-400  bg-violet-500/10',
  GEMINI:  'text-sky-400     bg-sky-500/10',
  COPILOT: 'text-blue-400    bg-blue-500/10',
  OTHER:   'text-slate-400   bg-slate-500/10',
};

const METHOD_COLORS = {
  CLIPBOARD:  'text-amber-400  bg-amber-500/10',
  SCREENSHOT: 'text-orange-400 bg-orange-500/10',
  BROWSER:    'text-sky-400    bg-sky-500/10',
  EXTENSION:  'text-violet-400 bg-violet-500/10',
};

function RiskBar({ score }) {
  const pct = Math.round((score ?? 0) * 100);
  const color = pct >= 70 ? 'bg-red-500' : pct >= 40 ? 'bg-amber-500' : 'bg-emerald-500';
  const text  = pct >= 70 ? 'text-red-400' : pct >= 40 ? 'text-amber-400' : 'text-emerald-400';
  return (
    <div className="flex items-center gap-2">
      <div className="w-16 h-1.5 bg-slate-700 rounded-full overflow-hidden">
        <div className={`h-full rounded-full ${color}`} style={{ width: `${pct}%` }} />
      </div>
      <span className={`text-xs font-semibold ${text}`}>{pct}%</span>
    </div>
  );
}

export default function AiPolicy() {
  const [attempts, setAttempts] = useState([]);
  const [total, setTotal]       = useState(0);
  const [loading, setLoading]   = useState(true);
  const [filter, setFilter]     = useState('');

  useEffect(() => {
    let cancelled = false;
    async function load() {
      try {
        const { data } = await api.get('/api/ai-policy/attempts?limit=50');
        if (!cancelled) { setAttempts(data.attempts ?? []); setTotal(data.total ?? 0); }
      } catch (e) { console.error(e); }
      finally { if (!cancelled) setLoading(false); }
    }
    load();
    return () => { cancelled = true; };
  }, []);

  const blocked   = attempts.filter(a => a.blocked).length;
  const displayed = filter ? attempts.filter(a => a.platform === filter) : attempts;

  return (
    <div className="p-6 max-w-7xl mx-auto">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-xl font-bold text-slate-100">AI Leak Policy</h1>
          <p className="text-sm text-slate-400 mt-0.5">Generative AI data exfiltration attempts · {total} detected</p>
        </div>
        <button onClick={() => window.location.reload()} className="btn-secondary flex items-center gap-2 text-sm">
          <RefreshCw size={14} />
        </button>
      </div>

      {/* Summary */}
      <div className="grid grid-cols-3 gap-4 mb-5">
        {[
          { label: 'Total Attempts', val: total,            color: 'text-indigo-400', icon: Brain      },
          { label: 'Blocked',        val: blocked,          color: 'text-red-400',    icon: ShieldX    },
          { label: 'Allowed',        val: total - blocked,  color: 'text-amber-400',  icon: ShieldCheck},
        ].map(({ label, val, color, icon: Icon }) => (
          <div key={label} className="card flex items-center gap-3">
            <div className="w-9 h-9 rounded-lg bg-slate-800 flex items-center justify-center">
              <Icon size={16} className={color} />
            </div>
            <div>
              <p className="text-xs text-slate-500">{label}</p>
              <p className={`text-xl font-bold ${color}`}>{val}</p>
            </div>
          </div>
        ))}
      </div>

      <div className="mb-4">
        <select className="select" value={filter} onChange={e => setFilter(e.target.value)}>
          <option value="">All Platforms</option>
          {['CHATGPT','CLAUDE','GEMINI','COPILOT','OTHER'].map(p =>
            <option key={p} value={p}>{p}</option>
          )}
        </select>
      </div>

      <div className="card p-0 overflow-hidden">
        <table className="w-full text-left">
          <thead>
            <tr className="border-b border-slate-800 bg-slate-900/50">
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
              <tr><td colSpan={7} className="text-center py-16">
                <div className="inline-block w-6 h-6 border-2 border-indigo-500 border-t-transparent
                                rounded-full animate-spin" />
              </td></tr>
            ) : displayed.length === 0 ? (
              <tr><td colSpan={7} className="text-center py-16 text-slate-500 text-sm">
                <Brain size={28} className="text-slate-700 mx-auto mb-2" />
                No AI leak attempts detected
              </td></tr>
            ) : displayed.map((att) => (
              <tr key={att.id} className="table-row cursor-default">
                <td className="td">
                  <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-semibold
                                   ${PLATFORM_COLORS[att.platform] ?? ''}`}>
                    {att.platform}
                  </span>
                </td>
                <td className="td">
                  <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium
                                   ${METHOD_COLORS[att.method] ?? ''}`}>
                    {att.method}
                  </span>
                </td>
                <td className="td"><RiskBar score={att.riskScore} /></td>
                <td className="td">
                  {att.blocked
                    ? <span className="flex items-center gap-1 text-xs text-red-400"><ShieldX size={12}/> Blocked</span>
                    : <span className="flex items-center gap-1 text-xs text-amber-400"><ShieldCheck size={12}/> Allowed</span>
                  }
                </td>
                <td className="td font-mono text-xs text-slate-400">{att.agent?.hostname ?? '—'}</td>
                <td className="td">
                  <span className="text-[10px] text-slate-500 font-mono max-w-[180px] block truncate">
                    {att.contentSample ?? '—'}
                  </span>
                </td>
                <td className="td text-xs text-slate-500">{formatDate(att.timestamp)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
