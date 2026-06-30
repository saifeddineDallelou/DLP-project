import { useEffect, useState } from 'react';
import {
  ResponsiveContainer, BarChart, Bar, XAxis, YAxis,
  CartesianGrid, Tooltip, Legend,
} from 'recharts';
import api from '../services/api.js';
import { SEVERITY_CHART_COLORS } from '../utils/format.js';

const CHANNELS = ['FILE', 'CLIPBOARD', 'USB', 'PRINT', 'SCREENSHOT', 'NETWORK'];

export default function Reports() {
  const [channelData, setChannelData] = useState([]);
  const [summary, setSummary]         = useState({ total: 0, blocked: 0, resolved: 0 });
  const [loading, setLoading]         = useState(true);

  useEffect(() => {
    let cancelled = false;
    async function load() {
      try {
        const { data } = await api.get('/api/incidents?limit=200');
        if (cancelled) return;
        const incidents = data.incidents ?? [];

        // Channel distribution
        const byChannel = CHANNELS.map(ch => ({
          channel: ch,
          LOW:      incidents.filter(i => i.channel === ch && i.severity === 'LOW').length,
          MEDIUM:   incidents.filter(i => i.channel === ch && i.severity === 'MEDIUM').length,
          HIGH:     incidents.filter(i => i.channel === ch && i.severity === 'HIGH').length,
          CRITICAL: incidents.filter(i => i.channel === ch && i.severity === 'CRITICAL').length,
        }));

        setSummary({
          total:    data.total,
          blocked:  incidents.filter(i => i.policy?.action === 'BLOCK').length,
          resolved: incidents.filter(i => i.status === 'RESOLVED').length,
        });
        setChannelData(byChannel);
      } catch (e) { console.error(e); }
      finally { if (!cancelled) setLoading(false); }
    }
    load();
    return () => { cancelled = true; };
  }, []);

  return (
    <div className="p-6 max-w-7xl mx-auto">
      <div className="mb-6">
        <h1 className="text-xl font-bold text-slate-100">Reports</h1>
        <p className="text-sm text-slate-400 mt-0.5">Security analytics &amp; trends</p>
      </div>

      <div className="grid grid-cols-3 gap-4 mb-6">
        {[
          { label: 'Total Incidents',  val: summary.total,    color: 'text-indigo-400' },
          { label: 'Blocked',          val: summary.blocked,  color: 'text-red-400'    },
          { label: 'Resolved',         val: summary.resolved, color: 'text-emerald-400'},
        ].map(({ label, val, color }) => (
          <div key={label} className="card text-center py-6">
            <p className={`text-3xl font-bold ${color}`}>{val}</p>
            <p className="text-xs text-slate-500 mt-1">{label}</p>
          </div>
        ))}
      </div>

      <div className="card">
        <h3 className="text-sm font-semibold text-slate-100 mb-4">
          Incidents by Channel &amp; Severity
        </h3>
        {loading ? (
          <div className="flex justify-center py-10">
            <div className="w-6 h-6 border-2 border-indigo-500 border-t-transparent rounded-full animate-spin" />
          </div>
        ) : (
          <ResponsiveContainer width="100%" height={280}>
            <BarChart data={channelData} margin={{ top: 4, right: 4, bottom: 0, left: -20 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
              <XAxis dataKey="channel" tick={{ fill: '#475569', fontSize: 11 }} axisLine={false} tickLine={false} />
              <YAxis tick={{ fill: '#475569', fontSize: 11 }} axisLine={false} tickLine={false} allowDecimals={false} />
              <Tooltip
                contentStyle={{ backgroundColor: '#1e293b', border: '1px solid #334155',
                                borderRadius: 8, fontSize: 12 }}
              />
              <Legend formatter={v => <span style={{ color: '#94a3b8', fontSize: 11 }}>{v}</span>} />
              <Bar dataKey="LOW"      fill={SEVERITY_CHART_COLORS.LOW}      radius={[3,3,0,0]} />
              <Bar dataKey="MEDIUM"   fill={SEVERITY_CHART_COLORS.MEDIUM}   radius={[3,3,0,0]} />
              <Bar dataKey="HIGH"     fill={SEVERITY_CHART_COLORS.HIGH}     radius={[3,3,0,0]} />
              <Bar dataKey="CRITICAL" fill={SEVERITY_CHART_COLORS.CRITICAL} radius={[3,3,0,0]} />
            </BarChart>
          </ResponsiveContainer>
        )}
      </div>
    </div>
  );
}
