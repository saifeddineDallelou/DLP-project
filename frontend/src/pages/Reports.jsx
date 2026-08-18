import { useEffect, useState } from 'react';
import { AlertTriangle, ShieldX, CheckCircle2 } from 'lucide-react';
import {
  ResponsiveContainer, BarChart, Bar, XAxis, YAxis,
  CartesianGrid, Tooltip, Legend,
} from 'recharts';
import api from '../services/api.js';
import PageHeader from '../components/PageHeader.jsx';
import StatCard from '../components/StatCard.jsx';
import Spinner from '../components/Spinner.jsx';

const CHANNELS = ['FILE', 'CLIPBOARD', 'USB', 'PRINT', 'SCREENSHOT', 'NETWORK'];
const SEVERITY_HEX = { LOW: '#2f9d5c', MEDIUM: '#ad8f1e', HIGH: '#c85a2e', CRITICAL: '#d03b3b' };

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
      <PageHeader title="Reports" sub="Security analytics & trends" />

      <div className="grid grid-cols-3 gap-4 mb-6">
        <StatCard icon={AlertTriangle} label="Total Incidents" value={summary.total}    tone="accent" />
        <StatCard icon={ShieldX}       label="Blocked"         value={summary.blocked}  tone="critical" />
        <StatCard icon={CheckCircle2}  label="Resolved"        value={summary.resolved} tone="low" />
      </div>

      <div className="card">
        <h3 className="text-sm font-semibold text-ink mb-1">Incidents by channel &amp; severity</h3>
        <p className="text-xs text-ink-faint mb-4">Last 200 incidents</p>
        {loading ? (
          <div className="flex justify-center py-10"><Spinner /></div>
        ) : (
          <ResponsiveContainer width="100%" height={280}>
            <BarChart data={channelData} margin={{ top: 4, right: 4, bottom: 0, left: -20 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#212b3a" vertical={false} />
              <XAxis dataKey="channel" tick={{ fill: '#66768a', fontSize: 11 }} axisLine={false} tickLine={false} />
              <YAxis tick={{ fill: '#66768a', fontSize: 11 }} axisLine={false} tickLine={false} allowDecimals={false} />
              <Tooltip
                contentStyle={{ backgroundColor: '#1a2330', border: '1px solid rgba(255,255,255,0.14)', borderRadius: 8, fontSize: 12 }}
                cursor={{ fill: 'rgba(255,255,255,0.03)' }}
              />
              <Legend formatter={v => <span style={{ color: '#9aa7b4', fontSize: 11 }}>{v}</span>} />
              <Bar dataKey="LOW"      stackId="sev" fill={SEVERITY_HEX.LOW} />
              <Bar dataKey="MEDIUM"   stackId="sev" fill={SEVERITY_HEX.MEDIUM} />
              <Bar dataKey="HIGH"     stackId="sev" fill={SEVERITY_HEX.HIGH} />
              <Bar dataKey="CRITICAL" stackId="sev" fill={SEVERITY_HEX.CRITICAL} radius={[3,3,0,0]} />
            </BarChart>
          </ResponsiveContainer>
        )}
      </div>
    </div>
  );
}
