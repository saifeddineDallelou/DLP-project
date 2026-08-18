import { useEffect, useState } from 'react';
import { AlertTriangle, Monitor, TrendingUp, ShieldAlert } from 'lucide-react';
import {
  ResponsiveContainer, LineChart, Line, XAxis, YAxis,
  CartesianGrid, Tooltip, PieChart, Pie, Cell, Legend,
} from 'recharts';
import api from '../services/api.js';
import PageHeader from '../components/PageHeader.jsx';
import StatCard from '../components/StatCard.jsx';
import Badge from '../components/Badge.jsx';
import Spinner from '../components/Spinner.jsx';
import { formatDate } from '../utils/format.js';

const SEVERITY_HEX = {
  LOW: '#2f9d5c', MEDIUM: '#ad8f1e', HIGH: '#c85a2e', CRITICAL: '#d03b3b',
};

function dayBuckets(incidents, days = 7) {
  const buckets = [];
  const now = new Date();
  for (let i = days - 1; i >= 0; i--) {
    const d = new Date(now);
    d.setDate(d.getDate() - i);
    d.setHours(0, 0, 0, 0);
    buckets.push({ key: d.toDateString(), date: d.toLocaleDateString('en-US', { month: 'short', day: 'numeric' }), scores: [] });
  }
  const byKey = Object.fromEntries(buckets.map((b) => [b.key, b]));
  incidents.forEach((inc) => {
    if (inc.riskScore == null) return;
    const d = new Date(inc.createdAt);
    d.setHours(0, 0, 0, 0);
    const bucket = byKey[d.toDateString()];
    if (bucket) bucket.scores.push(inc.riskScore);
  });
  return buckets.map((b) => ({
    date: b.date,
    avgRisk: b.scores.length ? b.scores.reduce((a, c) => a + c, 0) / b.scores.length : 0,
    count: b.scores.length,
  }));
}

const CustomTooltip = ({ active, payload, label }) => {
  if (!active || !payload?.length) return null;
  const p = payload[0].payload;
  return (
    <div className="bg-surface-elevated border border-border-strong rounded-lg px-3 py-2 text-xs shadow-elevated">
      <p className="text-ink-faint mb-1">{label}</p>
      <p className="text-accent-text font-semibold">Avg risk: {(p.avgRisk * 100).toFixed(0)}%</p>
      <p className="text-ink-faint mt-0.5">{p.count} incident{p.count === 1 ? '' : 's'}</p>
    </div>
  );
};

export default function Dashboard() {
  const [stats, setStats]     = useState({ total: 0, open: 0, agents: 0, avgRisk: 0 });
  const [recent, setRecent]   = useState([]);
  const [trend, setTrend]     = useState([]);
  const [severityDist, setSeverity] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;
    async function fetchAll() {
      try {
        const [allRes, openRes, agentsRes, recentRes] = await Promise.all([
          api.get('/api/incidents?limit=200'),
          api.get('/api/incidents?status=OPEN&limit=1'),
          api.get('/api/agents'),
          api.get('/api/incidents?limit=5'),
        ]);
        if (cancelled) return;

        const incidents = allRes.data.incidents ?? [];
        const activeAgents = (agentsRes.data ?? []).filter(a => a.status === 'ACTIVE').length;
        const riskScores = incidents.map(i => i.riskScore).filter((v) => v != null);
        const avgRisk = riskScores.length
          ? riskScores.reduce((a, b) => a + b, 0) / riskScores.length
          : 0;

        const dist = {};
        incidents.forEach(i => { dist[i.severity] = (dist[i.severity] ?? 0) + 1; });
        const pieData = Object.entries(dist).map(([name, value]) => ({
          name, value, fill: SEVERITY_HEX[name] ?? '#66768a',
        }));

        setStats({
          total: allRes.data.total ?? 0,
          open: openRes.data.total ?? 0,
          agents: activeAgents,
          avgRisk: avgRisk.toFixed(2),
        });
        setRecent(recentRes.data.incidents ?? []);
        setSeverity(pieData);
        setTrend(dayBuckets(incidents));
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
      <PageHeader title="Dashboard" sub="Security operations overview" />

      {/* Stats */}
      <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4 mb-6">
        <StatCard icon={AlertTriangle} label="Total Incidents" value={stats.total} tone="critical" />
        <StatCard icon={ShieldAlert}   label="Open Incidents"  value={stats.open}  tone="medium" />
        <StatCard icon={Monitor}       label="Active Agents"   value={stats.agents} tone="low" />
        <StatCard icon={TrendingUp}    label="Avg Risk Score"  value={stats.avgRisk} tone="accent" sub="Across all tracked incidents" />
      </div>

      {/* Charts */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4 mb-6">
        <div className="card lg:col-span-2">
          <div className="mb-4">
            <h3 className="text-sm font-semibold text-ink">Risk score trend</h3>
            <p className="text-xs text-ink-faint">Average risk score of incidents created per day, last 7 days</p>
          </div>
          <ResponsiveContainer width="100%" height={190}>
            <LineChart data={trend} margin={{ top: 4, right: 4, bottom: 0, left: -20 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#212b3a" vertical={false} />
              <XAxis dataKey="date" tick={{ fill: '#66768a', fontSize: 11 }} axisLine={false} tickLine={false} />
              <YAxis domain={[0, 1]} tick={{ fill: '#66768a', fontSize: 11 }} axisLine={false} tickLine={false}
                     tickFormatter={v => `${(v*100).toFixed(0)}%`} />
              <Tooltip content={<CustomTooltip />} cursor={{ stroke: '#35b7be', strokeWidth: 1, strokeDasharray: '3 3' }} />
              <Line
                type="monotone" dataKey="avgRisk" stroke="#35b7be" strokeWidth={2}
                dot={{ r: 3, fill: '#35b7be', strokeWidth: 0 }}
                activeDot={{ r: 5, fill: '#5fd1d7' }}
              />
            </LineChart>
          </ResponsiveContainer>
        </div>

        <div className="card">
          <h3 className="text-sm font-semibold text-ink mb-1">Incidents by severity</h3>
          <p className="text-xs text-ink-faint mb-3">Last 200 incidents</p>
          {severityDist.length === 0 ? (
            <div className="flex items-center justify-center h-44 text-ink-faint text-sm">No incident data</div>
          ) : (
            <ResponsiveContainer width="100%" height={190}>
              <PieChart>
                <Pie data={severityDist} cx="50%" cy="45%" innerRadius={52} outerRadius={72} dataKey="value" paddingAngle={3}>
                  {severityDist.map((entry, i) => <Cell key={i} fill={entry.fill} stroke="transparent" />)}
                </Pie>
                <Legend iconType="circle" iconSize={8}
                  formatter={(v) => <span style={{ color: '#9aa7b4', fontSize: 11 }}>{v}</span>} />
                <Tooltip contentStyle={{ backgroundColor: '#1a2330', border: '1px solid rgba(255,255,255,0.14)', borderRadius: 8, fontSize: 12 }} />
              </PieChart>
            </ResponsiveContainer>
          )}
        </div>
      </div>

      {/* Recent Incidents */}
      <div className="card">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-sm font-semibold text-ink">Recent incidents</h3>
          <a href="/incidents" className="text-xs text-accent-text hover:underline">View all →</a>
        </div>
        {loading ? (
          <div className="flex items-center justify-center py-10"><Spinner /></div>
        ) : recent.length === 0 ? (
          <p className="text-ink-faint text-sm text-center py-8">No incidents yet</p>
        ) : (
          <table className="w-full text-left">
            <thead>
              <tr className="border-b border-border">
                <th className="th">Severity</th>
                <th className="th">Channel</th>
                <th className="th">Status</th>
                <th className="th">Agent</th>
                <th className="th">Created</th>
              </tr>
            </thead>
            <tbody>
              {recent.map((inc) => (
                <tr key={inc.id} className="border-b border-border/60 hover:bg-surface-hover/40 transition-colors">
                  <td className="td"><Badge tone="severity" value={inc.severity} size="sm" /></td>
                  <td className="td text-ink-faint">{inc.channel}</td>
                  <td className="td"><Badge tone="status" value={inc.status} size="sm" /></td>
                  <td className="td font-mono text-xs">{inc.agent?.hostname ?? '—'}</td>
                  <td className="td text-ink-faint text-xs">{formatDate(inc.createdAt)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
