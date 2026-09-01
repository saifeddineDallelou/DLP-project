import { useEffect, useState, useCallback } from 'react';
import { Activity, RefreshCw, TrendingUp, User, Calculator } from 'lucide-react';
import api from '../services/api.js';
import PageHeader from '../components/PageHeader.jsx';
import EmptyState from '../components/EmptyState.jsx';
import Spinner from '../components/Spinner.jsx';
import RiskBar from '../components/RiskBar.jsx';
import EventMetadata from '../components/EventMetadata.jsx';
import { formatDate, EVENT_TYPE_LABELS, RISK_LEVEL_TONES } from '../utils/format.js';

function RiskProfileCard({ profile, onRecompute, recomputing }) {
  const tone = RISK_LEVEL_TONES[profile.riskLevel] ?? RISK_LEVEL_TONES.LOW;
  return (
    <div className="card">
      <div className="flex items-center gap-2.5 mb-3">
        <div className="w-8 h-8 rounded-full bg-surface-elevated flex items-center justify-center shrink-0">
          <User size={14} className="text-ink-faint" />
        </div>
        <div className="min-w-0 flex-1">
          <p className="text-sm font-medium text-ink truncate" title={profile.userId}>
            {profile.userId}
          </p>
          <p className="text-[11px] text-ink-faint">
            {profile.last24h.total} event{profile.last24h.total === 1 ? '' : 's'} · last 24h
          </p>
        </div>
        <span className={`badge text-[10px] ${tone.text} bg-white/5`}>{profile.riskLevel}</span>
      </div>

      <div className="flex items-end justify-between mb-2">
        <span className="text-[11px] text-ink-faint">Live risk score</span>
        <span className={`text-lg font-bold tabular-nums ${tone.text}`}>
          {Math.round(profile.liveRiskScore * 100)}%
        </span>
      </div>
      <div className="w-full h-2 bg-surface-elevated rounded-full overflow-hidden mb-3">
        <div className={`h-full rounded-full ${tone.bar} transition-all duration-500`}
             style={{ width: `${Math.round(profile.liveRiskScore * 100)}%` }} />
      </div>

      <div className="grid grid-cols-4 gap-2 text-center pt-2 border-t border-border">
        <div>
          <p className="text-xs font-semibold text-ink tabular-nums">{profile.baselineRiskScore.toFixed(2)}</p>
          <p className="text-[9px] text-ink-faint uppercase tracking-wide mt-0.5">Baseline</p>
        </div>
        <div>
          <p className="text-xs font-semibold text-ink tabular-nums">{profile.last24h.afterHoursAccess}</p>
          <p className="text-[9px] text-ink-faint uppercase tracking-wide mt-0.5">After-hrs</p>
        </div>
        <div>
          <p className="text-xs font-semibold text-ink tabular-nums">{profile.last24h.usbInserts}</p>
          <p className="text-[9px] text-ink-faint uppercase tracking-wide mt-0.5">USB</p>
        </div>
        <div>
          <p className="text-xs font-semibold text-ink tabular-nums">{profile.last24h.largeFileTransfers}</p>
          <p className="text-[9px] text-ink-faint uppercase tracking-wide mt-0.5">Large files</p>
        </div>
      </div>

      {profile.baseline && (
        <div className="grid grid-cols-4 gap-2 text-center pt-2 mt-2 border-t border-border">
          <div>
            <p className="text-xs font-semibold text-ink tabular-nums">{profile.baseline.avgDailyFiles}</p>
            <p className="text-[9px] text-ink-faint uppercase tracking-wide mt-0.5">Files/day</p>
          </div>
          <div>
            <p className="text-xs font-semibold text-ink tabular-nums">{profile.baseline.avgDailyVolumeMB}</p>
            <p className="text-[9px] text-ink-faint uppercase tracking-wide mt-0.5">MB/day</p>
          </div>
          <div>
            <p className="text-xs font-semibold text-ink tabular-nums">
              {profile.baseline.avgWorkingHourStart}–{profile.baseline.avgWorkingHourEnd}h
            </p>
            <p className="text-[9px] text-ink-faint uppercase tracking-wide mt-0.5">Active hours</p>
          </div>
          <div>
            <p className="text-xs font-semibold text-ink tabular-nums">{profile.baseline.avgUsbFrequency}</p>
            <p className="text-[9px] text-ink-faint uppercase tracking-wide mt-0.5">USB/day</p>
          </div>
        </div>
      )}

      <button
        className="btn-secondary text-[11px] w-full mt-3 py-1.5"
        disabled={recomputing}
        onClick={() => onRecompute(profile.userId)}
        title="Recompute avgDailyFiles / working hours / USB frequency from this user's actual event history"
      >
        <Calculator size={12} /> {recomputing ? 'Recomputing…' : 'Recompute baseline from history'}
      </button>
    </div>
  );
}

export default function UEBA() {
  const [events, setEvents]     = useState([]);
  const [total, setTotal]       = useState(0);
  const [profiles, setProfiles] = useState([]);
  const [loading, setLoading]   = useState(true);
  const [profilesLoading, setProfilesLoading] = useState(true);
  const [filter, setFilter]     = useState('');
  const [recomputingId, setRecomputingId] = useState(null);

  const load = useCallback(async () => {
    setLoading(true);
    setProfilesLoading(true);
    try {
      const { data } = await api.get('/api/ueba/events?limit=100');
      const evs = data.events ?? [];
      setEvents(evs);
      setTotal(data.total ?? 0);
      setLoading(false);

      const userIds = [...new Set(evs.map((e) => e.userId))];
      const results = await Promise.all(
        userIds.map((id) =>
          api.get(`/api/ueba/risk-score/${id}`).then((r) => r.data).catch(() => null)
        )
      );
      const withProfiles = results
        .filter(Boolean)
        .sort((a, b) => b.liveRiskScore - a.liveRiskScore);
      setProfiles(withProfiles);
    } catch (e) {
      console.error(e);
      setLoading(false);
    } finally {
      setProfilesLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  const recompute = async (userId) => {
    setRecomputingId(userId);
    try {
      await api.post(`/api/ueba/baseline/${userId}/recompute`);
      await load();
    } catch (e) {
      console.error(e);
    } finally {
      setRecomputingId(null);
    }
  };

  const displayed = filter
    ? events.filter(e => e.eventType === filter || e.userId?.includes(filter))
    : events;

  return (
    <div className="p-6 max-w-7xl mx-auto">
      <PageHeader title="UEBA" sub={`User & Entity Behavior Analytics · ${total} events tracked`}>
        <button onClick={load} className="btn-secondary">
          <RefreshCw size={14} />
        </button>
      </PageHeader>

      {/* Risk profiles */}
      <div className="mb-6">
        <div className="flex items-center gap-2 mb-3">
          <TrendingUp size={14} className="text-ink-faint" />
          <h2 className="text-sm font-semibold text-ink">Behavioral risk by user</h2>
        </div>
        {profilesLoading ? (
          <div className="flex justify-center py-10"><Spinner /></div>
        ) : profiles.length === 0 ? (
          <div className="card">
            <EmptyState icon={User} title="No user risk profiles yet"
              sub="Risk profiles appear once behavior events have been recorded for a user." />
          </div>
        ) : (
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
            {profiles.map((p) => (
              <RiskProfileCard
                key={p.userId}
                profile={p}
                onRecompute={recompute}
                recomputing={recomputingId === p.userId}
              />
            ))}
          </div>
        )}
      </div>

      {/* Event log */}
      <div className="flex items-center justify-between mb-3">
        <h2 className="text-sm font-semibold text-ink">Behavior event log</h2>
        <select className="select" value={filter} onChange={e => setFilter(e.target.value)}>
          <option value="">All event types</option>
          {Object.entries(EVENT_TYPE_LABELS).map(([t, label]) => (
            <option key={t} value={t}>{label}</option>
          ))}
        </select>
      </div>

      <div className="card p-0 overflow-hidden">
        <table className="w-full text-left">
          <thead>
            <tr className="border-b border-border bg-surface-elevated/50">
              <th className="th">Event type</th>
              <th className="th">User</th>
              <th className="th">Agent</th>
              <th className="th">Details</th>
              <th className="th">Timestamp</th>
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr><td colSpan={5} className="text-center py-16"><Spinner /></td></tr>
            ) : displayed.length === 0 ? (
              <tr><td colSpan={5}>
                <EmptyState icon={Activity} title="No behavior events recorded" />
              </td></tr>
            ) : displayed.map((ev) => (
              <tr key={ev.id} className="table-row cursor-default">
                <td className="td">
                  <span className="badge text-[11px] bg-white/5 text-ink-soft">
                    {EVENT_TYPE_LABELS[ev.eventType] ?? ev.eventType.replace(/_/g, ' ')}
                  </span>
                </td>
                <td className="td font-mono text-xs text-ink">{ev.userId}</td>
                <td className="td text-xs text-ink-faint">{ev.agent?.hostname ?? '—'}</td>
                <td className="td"><EventMetadata metadata={ev.metadata} /></td>
                <td className="td text-xs text-ink-faint">{formatDate(ev.timestamp)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Formula reference, not chart-adjacent — earns its place as a footnote for the demo */}
      <p className="text-[11px] text-ink-faint mt-3 text-center">
        Live score = baseline + 0.1 × after-hours events (24h) + 0.05 × USB inserts (24h), capped at 1.0
      </p>
    </div>
  );
}
