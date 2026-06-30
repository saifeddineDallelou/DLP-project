import { useEffect, useState } from 'react';
import {
  AlertTriangle, Activity, Monitor, TrendingUp,
  ArrowUpRight, ArrowDownRight,
} from 'lucide-react';
import {
  ResponsiveContainer, LineChart, Line, XAxis, YAxis,
  CartesianGrid, Tooltip, PieChart, Pie, Cell, Legend,
} from 'recharts';
import api from '../services/api.js';
import { formatDate, SEVERITY_STYLES, STATUS_STYLES, SEVERITY_CHART_COLORS } from '../utils/format.js';

// 7-day mock risk trend
const RISK_TREND = [
  { date: 'Jun 24', risk: 0.38 },
  { date: 'Jun 25', risk: 0.42 },
  { date: 'Jun 26', risk: 0.55 },
  { date: 'Jun 27', risk: 0.48 },
  { date: 'Jun 28', risk: 0.61 },
  { date: 'Jun 29', risk: 0.53 },
  { date: 'Jun 30', risk: 0.72 },
];

function StatCard({ icon: Icon, label, value, sub, color = 'indigo', trend }) {
  const colors = {
    indigo: 'bg-indigo-500/10 text-indigo-400',
    red:    'bg-red-500/10    text-red-400',
    green:  'bg-emerald-500/10 text-emerald-400',
    amber:  'bg-amber-500/10  text-amber-400',
  };
  return (
    <div className="card flex items-start gap-4">
      <div className={`w-10 h-10 rounded-lg flex items-center justify-center shrink-0 ${colors[color]}`}>
        <Icon size={18} />
      </div>
      <div className="flex-1 min-w-0">
        <p className="text-xs text-slate-500 font-medium mb-0.5">{label}</p>
        <p className="text-2xl font-bold text-slate-100">{value ?? '—'}</p>
        {sub && <p className="text-xs text-slate-500 mt-0.5">{sub}</p>}
      </div>
      {trend !== undefined && (
        <div className={`flex items-center gap-1 text-xs font-medium ${
          trend >= 0 ? 'text-red-400' : 'text-emerald-400'
        }`}>
          {trend >= 0 ? <ArrowUpRight size={14}/> : <ArrowDownRight size={14}/>}
          {Math.abs(trend)}%
        </div>
      )}
    </div>
  );
}

const CustomTooltip = ({ active, payload, label }) => {
  if (!active || !payload?.length) return null;
  return (
    <div className="bg-slate-800 border border-slate-700 rounded-lg px-3 py-2 text-xs">
      <p className="text-slate-400 mb-1">{label}</p>
      <p className="text-indigo-400 font-semibold">Risk: {(payload[0].value * 100).toFixed(0)}%</p>
    </div>
  );
};

export default function Dashboard() {
  const [stats, setStats]           = useState({ total: 0, open: 0, agents: 0, avgRisk: 0 });
  const [recent, setRecent]         = useState([]);
  const [severityDist, setSeverity] = useState([]);
  const [loading, setLoading]       = useState(true);

  useEffect(() => {
    let cancelled = false;
    async function fetchAll() {
      try {
        const [allRes, openRes, agentsRes] = await Promise.all([
          api.get('/api/incidents?limit=5'),
          api.get('/api/incidents?status=OPEN&limit=1'),
          api.get('/api/agents'),
        ]);
        if (cancelled) return;

        const incidents  = allRes.data.incidents ?? [];
        const activeAgents = (agentsRes.data ?? []).filter(a => a.status === 'ACTIVE').length;
        const riskScores = incidents.map(i => i.riskScore).filter(Boolean);
        const avgRisk    = riskScores.length
          ? riskScores.reduce((a, b) => a + b, 0) / riskScores.length
          : 0;

        // Severity distribution
        const dist = {};
        incidents.forEach(i => { dist[i.severity] = (dist[i.severity] ?? 0) + 1; });
        const pieData = Object.entries(dist).map(([name, value]) => ({
          name, value, fill: SEVERITY_CHART_COLORS[name] ?? '#94a3b8',
        }));

        setStats({
          total:   allRes.data.total ?? 0,
          open:    openRes.data.total ?? 0,
          agents:  activeAgents,
          avgRisk: avgRisk.toFixed(2),
        });
        setRecent(incidents.slice(0, 5));
        setSeverity(pieData);
      } catch (e) {
        console.error(e);
      } finally {
        if (!cancelled) setLoading(false);
      }
    }
    fetchAll();
    return () => { cancelled = true; };
  }, []);

  return (
    <div className="p-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="mb-6">
        <h1 className="text-xl font-bold text-slate-100">Dashboard</h1>
        <p className="text-sm text-slate-400 mt-0.5">Security operations overview</p>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4 mb-6">
        <StatCard icon={AlertTriangle} label="Total Incidents"  value={stats.total}   color="red"    trend={12} />
        <StatCard icon={AlertTriangle} label="Open Incidents"   value={stats.open}    color="amber"  />
        <StatCard icon={Monitor}       label="Active Agents"    value={stats.agents}  color="green"  />
        <StatCard icon={TrendingUp}    label="Avg Risk Score"   value={stats.avgRisk} color="indigo" />
      </div>

      {/* Charts */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4 mb-6">
        {/* Risk trend */}
        <div className="card lg:col-span-2">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h3 className="text-sm font-semibold text-slate-100">Risk Score Trend</h3>
              <p className="text-xs text-slate-500">Last 7 days · mock data</p>
            </div>
          </div>
          <ResponsiveContainer width="100%" height={190}>
            <LineChart data={RISK_TREND} margin={{ top: 4, right: 4, bottom: 0, left: -20 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
              <XAxis dataKey="date" tick={{ fill: '#475569', fontSize: 11 }} axisLine={false} tickLine={false} />
              <YAxis domain={[0, 1]} tick={{ fill: '#475569', fontSize: 11 }} axisLine={false} tickLine={false}
                     tickFormatter={v => `${(v*100).toFixed(0)}%`} />
              <Tooltip content={<CustomTooltip />} />
              <Line
                type="monotone" dataKey="risk" stroke="#6366f1" strokeWidth={2}
                dot={{ r: 3, fill: '#6366f1', strokeWidth: 0 }}
                activeDot={{ r: 5, fill: '#818cf8' }}
              />
            </LineChart>
          </ResponsiveContainer>
        </div>

        {/* Severity pie */}
        <div className="card">
          <h3 className="text-sm font-semibold text-slate-100 mb-1">Incidents by Severity</h3>
          <p className="text-xs text-slate-500 mb-3">Current period</p>
          {severityDist.length === 0 ? (
            <div className="flex items-center justify-center h-44 text-slate-600 text-sm">
              No incident data
            </div>
          ) : (
            <ResponsiveContainer width="100%" height={190}>
              <PieChart>
                <Pie
                  data={severityDist} cx="50%" cy="45%"
                  innerRadius={52} outerRadius={72}
                  dataKey="value" paddingAngle={3}
                >
                  {severityDist.map((entry, i) => (
                    <Cell key={i} fill={entry.fill} stroke="transparent" />
                  ))}
                </Pie>
                <Legend
                  iconType="circle" iconSize={8}
                  formatter={(v) => <span style={{ color: '#94a3b8', fontSize: 11 }}>{v}</span>}
                />
                <Tooltip
                  contentStyle={{ backgroundColor: '#1e293b', border: '1px solid #334155',
                                  borderRadius: 8, fontSize: 12 }}
                />
              </PieChart>
            </ResponsiveContainer>
          )}
        </div>
      </div>

      {/* Recent Incidents */}
      <div className="card">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-sm font-semibold text-slate-100">Recent Incidents</h3>
          <a href="/incidents" className="text-xs text-indigo-400 hover:text-indigo-300">View all →</a>
        </div>
        {loading ? (
          <div className="flex items-center justify-center py-10">
            <div className="w-6 h-6 border-2 border-indigo-500 border-t-transparent rounded-full animate-spin" />
          </div>
        ) : recent.length === 0 ? (
          <p className="text-slate-500 text-sm text-center py-8">No incidents yet</p>
        ) : (
          <table className="w-full text-left">
            <thead>
              <tr className="border-b border-slate-800">
                <th className="th">Severity</th>
                <th className="th">Channel</th>
                <th className="th">Status</th>
                <th className="th">Agent</th>
                <th className="th">Created</th>
              </tr>
            </thead>
            <tbody>
              {recent.map((inc) => (
                <tr key={inc.id} className="border-b border-slate-800/60 hover:bg-slate-800/40 transition-colors">
                  <td className="td">
                    <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium
                                     border ${SEVERITY_STYLES[inc.severity]}`}>
                      {inc.severity}
                    </span>
                  </td>
                  <td className="td text-slate-400">{inc.channel}</td>
                  <td className="td">
                    <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium
                                     border ${STATUS_STYLES[inc.status]}`}>
                      {inc.status.replace('_', ' ')}
                    </span>
                  </td>
                  <td className="td font-mono text-xs">{inc.agent?.hostname ?? '—'}</td>
                  <td className="td text-slate-500 text-xs">{formatDate(inc.createdAt)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
