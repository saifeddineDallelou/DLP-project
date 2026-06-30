import { useEffect, useState } from 'react';
import { Activity, RefreshCw, AlertTriangle } from 'lucide-react';
import api from '../services/api.js';
import { formatDate } from '../utils/format.js';

const EVENT_COLORS = {
  FILE_ACCESS:        'text-sky-400     bg-sky-500/10',
  USB_INSERT:         'text-orange-400  bg-orange-500/10',
  CLIPBOARD_COPY:     'text-amber-400   bg-amber-500/10',
  SCREENSHOT:         'text-violet-400  bg-violet-500/10',
  APP_LAUNCH:         'text-slate-400   bg-slate-500/10',
  AFTER_HOURS_ACCESS: 'text-red-400     bg-red-500/10',
};

function RiskLevel({ score }) {
  const pct = Math.round((score ?? 0) * 100);
  const color = pct >= 70 ? 'text-red-400' : pct >= 40 ? 'text-amber-400' : 'text-emerald-400';
  const bar   = pct >= 70 ? 'bg-red-500'   : pct >= 40 ? 'bg-amber-500'   : 'bg-emerald-500';
  return (
    <div className="flex items-center gap-2">
      <div className="w-20 h-1.5 bg-slate-700 rounded-full overflow-hidden">
        <div className={`h-full rounded-full ${bar}`} style={{ width: `${pct}%` }} />
      </div>
      <span className={`text-xs font-semibold ${color}`}>{pct}%</span>
    </div>
  );
}

export default function UEBA() {
  const [events, setEvents]   = useState([]);
  const [total, setTotal]     = useState(0);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter]   = useState('');

  useEffect(() => {
    let cancelled = false;
    async function load() {
      try {
        const { data } = await api.get('/api/ueba/events?limit=50');
        if (!cancelled) { setEvents(data.events ?? []); setTotal(data.total ?? 0); }
      } catch (e) { console.error(e); }
      finally { if (!cancelled) setLoading(false); }
    }
    load();
    return () => { cancelled = true; };
  }, []);

  const displayed = filter
    ? events.filter(e => e.eventType === filter || e.userId?.includes(filter))
    : events;

  return (
    <div className="p-6 max-w-7xl mx-auto">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-xl font-bold text-slate-100">UEBA</h1>
          <p className="text-sm text-slate-400 mt-0.5">User &amp; Entity Behavior Analytics · {total} events</p>
        </div>
        <button onClick={() => window.location.reload()} className="btn-secondary flex items-center gap-2 text-sm">
          <RefreshCw size={14} />
        </button>
      </div>

      <div className="mb-4">
        <select
          className="select"
          value={filter}
          onChange={e => setFilter(e.target.value)}
        >
          <option value="">All Event Types</option>
          {Object.keys(EVENT_COLORS).map(t => <option key={t} value={t}>{t.replace(/_/g, ' ')}</option>)}
        </select>
      </div>

      <div className="card p-0 overflow-hidden">
        <table className="w-full text-left">
          <thead>
            <tr className="border-b border-slate-800 bg-slate-900/50">
              <th className="th">Event Type</th>
              <th className="th">User</th>
              <th className="th">Agent</th>
              <th className="th">Metadata</th>
              <th className="th">Timestamp</th>
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr><td colSpan={5} className="text-center py-16">
                <div className="inline-block w-6 h-6 border-2 border-indigo-500 border-t-transparent
                                rounded-full animate-spin" />
              </td></tr>
            ) : displayed.length === 0 ? (
              <tr><td colSpan={5} className="text-center py-16 text-slate-500 text-sm">
                <Activity size={28} className="text-slate-700 mx-auto mb-2" />
                No behavior events recorded
              </td></tr>
            ) : displayed.map((ev) => (
              <tr key={ev.id} className="table-row cursor-default">
                <td className="td">
                  <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium
                                   ${EVENT_COLORS[ev.eventType] ?? 'text-slate-400 bg-slate-800'}`}>
                    {ev.eventType.replace(/_/g, ' ')}
                  </span>
                </td>
                <td className="td font-mono text-xs text-slate-300">{ev.userId}</td>
                <td className="td text-xs text-slate-400">{ev.agent?.hostname ?? '—'}</td>
                <td className="td">
                  <pre className="text-[10px] text-slate-500 font-mono max-w-[200px] overflow-hidden truncate">
                    {JSON.stringify(ev.metadata)}
                  </pre>
                </td>
                <td className="td text-xs text-slate-500">{formatDate(ev.timestamp)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
