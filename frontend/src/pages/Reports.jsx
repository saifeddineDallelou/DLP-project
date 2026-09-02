import { Fragment, useEffect, useState } from 'react';
import { AlertTriangle, ShieldX, CheckCircle2, Flag, ClipboardList } from 'lucide-react';
import {
  ResponsiveContainer, BarChart, Bar, XAxis, YAxis,
  CartesianGrid, Tooltip, Legend,
} from 'recharts';
import api from '../services/api.js';
import Modal from '../components/Modal.jsx';
import PageHeader from '../components/PageHeader.jsx';
import StatCard from '../components/StatCard.jsx';
import Spinner from '../components/Spinner.jsx';
import EmptyState from '../components/EmptyState.jsx';
import { formatDate, PLATFORM_LABELS } from '../utils/format.js';

const CHANNELS = ['FILE', 'CLIPBOARD', 'USB', 'PRINT', 'SCREENSHOT', 'NETWORK'];
const SEVERITY_HEX = { LOW: '#2f9d5c', MEDIUM: '#ad8f1e', HIGH: '#c85a2e', CRITICAL: '#d03b3b' };

function todayStr() {
  return new Date().toISOString().slice(0, 10);
}

function DailyReport() {
  const [date, setDate]         = useState(todayStr());
  const [report, setReport]     = useState(null);
  const [loading, setLoading]   = useState(true);
  const [selected, setSelected] = useState(null);
  const [adminNoteDraft, setAdminNoteDraft] = useState('');
  const [updating, setUpdating] = useState(false);

  const load = async (d) => {
    setLoading(true);
    try {
      const { data } = await api.get(`/api/reports/daily?date=${d}`);
      setReport(data);
    } catch (e) { console.error(e); }
    finally { setLoading(false); }
  };

  useEffect(() => { load(date); }, [date]);

  const openDetail = (item) => {
    setSelected(item);
    setAdminNoteDraft(item.adminNote ?? '');
  };

  const saveAdminNote = async () => {
    if (!selected) return;
    setUpdating(true);
    try {
      const path = selected.kind === 'INCIDENT'
        ? `/api/incidents/${selected.id}`
        : `/api/ai-policy/attempt/${selected.id}`;
      const { data } = await api.patch(path, { adminNote: adminNoteDraft });
      setSelected((s) => ({ ...s, ...data }));
      setReport((r) => ({
        ...r,
        timeline: r.timeline.map((t) => (t.id === selected.id ? { ...t, adminNote: data.adminNote } : t)),
      }));
    } catch (e) { console.error(e); }
    finally { setUpdating(false); }
  };

  return (
    <div className="card">
      <div className="flex items-center justify-between mb-1">
        <h3 className="text-sm font-semibold text-ink">Daily digest</h3>
        <input
          type="date"
          className="input text-xs !w-auto"
          value={date}
          max={todayStr()}
          onChange={(e) => setDate(e.target.value)}
        />
      </div>
      <p className="text-xs text-ink-faint mb-4">Everything that happened on {date}, in order</p>

      {loading ? (
        <div className="flex justify-center py-10"><Spinner /></div>
      ) : !report || report.timeline.length === 0 ? (
        <EmptyState icon={ClipboardList} title="Nothing happened on this day" />
      ) : (
        <>
          <div className="grid grid-cols-4 gap-3 mb-4">
            <StatCard icon={AlertTriangle} label="Incidents"        value={report.summary.totalIncidents}       tone="accent" />
            <StatCard icon={ShieldX}       label="AI leak attempts" value={report.summary.totalAiLeakAttempts}  tone="critical" />
            <StatCard icon={Flag}          label="Review requested" value={report.summary.reviewRequested}      tone="medium" />
            <StatCard icon={CheckCircle2}  label="Needs admin note" value={report.summary.needsAdminNote}       tone="medium" />
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left">
              <thead>
                <tr className="border-b border-border">
                  <th className="th">Time</th>
                  <th className="th">Type</th>
                  <th className="th">Source</th>
                  <th className="th">Status</th>
                  <th className="th">Agent</th>
                  <th className="th">Policy</th>
                  <th className="th">Note</th>
                </tr>
              </thead>
              <tbody>
                {report.timeline.map((item) => (
                  <tr key={`${item.kind}-${item.id}`} className="table-row" onClick={() => openDetail(item)}>
                    <td className="td text-xs text-ink-faint whitespace-nowrap">{formatDate(item.time)}</td>
                    <td className="td text-xs text-ink-faint">{item.kind === 'INCIDENT' ? 'Incident' : 'AI leak attempt'}</td>
                    <td className="td text-xs text-ink-faint">
                      {item.kind === 'INCIDENT' ? item.channel : (PLATFORM_LABELS[item.channel] ?? item.channel)}
                    </td>
                    <td className="td">
                      <div className="flex items-center gap-1.5">
                        <span className="text-xs text-ink-faint">{item.status?.replace('_', ' ')}</span>
                        {item.reviewRequested && (
                          <span title="Worker flagged this for review" className="text-severity-medium-text">
                            <Flag size={12} />
                          </span>
                        )}
                      </div>
                    </td>
                    <td className="td font-mono text-xs text-ink-faint">{item.agent?.hostname ?? '—'}</td>
                    <td className="td text-xs text-ink-faint truncate max-w-[140px]">{item.policy?.name ?? '—'}</td>
                    <td className="td text-xs text-ink-faint truncate max-w-[160px]">{item.adminNote || '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}

      <Modal open={!!selected} onClose={() => setSelected(null)} title="Event detail" maxWidth="max-w-xl">
        {selected && (
          <div className="space-y-4">
            <div className="grid grid-cols-2 gap-3 text-sm">
              {[
                ['Type',   selected.kind === 'INCIDENT' ? 'Incident' : 'AI leak attempt'],
                ['Time',   formatDate(selected.time)],
                ['Source', selected.kind === 'INCIDENT' ? selected.channel : (PLATFORM_LABELS[selected.channel] ?? selected.channel)],
                ['Status', selected.status?.replace('_', ' ')],
                ['Agent',  selected.agent?.hostname ?? '—'],
                ['Policy', selected.policy?.name ?? '—'],
              ].map(([k, v]) => (
                <div key={k} className="bg-surface-elevated border border-border rounded-lg p-3">
                  <p className="text-[10px] font-semibold text-ink-faint uppercase tracking-wider mb-0.5">{k}</p>
                  <p className="text-ink text-xs break-all">{v}</p>
                </div>
              ))}
            </div>

            {selected.reviewRequested && (
              <div className="bg-severity-medium-soft border border-severity-medium/25 rounded-lg p-3">
                <p className="text-[10px] font-semibold text-severity-medium-text uppercase tracking-wider mb-1 flex items-center gap-1">
                  <Flag size={11} /> Worker flagged this for review
                </p>
                <p className="text-xs text-ink break-words">
                  {selected.justification || <span className="text-ink-faint italic">No note left</span>}
                </p>
              </div>
            )}

            <div>
              <p className="label mb-1.5">Admin note</p>
              <textarea
                className="input w-full text-xs resize-none"
                rows={3}
                placeholder="Record what you found and the disposition..."
                value={adminNoteDraft}
                onChange={(e) => setAdminNoteDraft(e.target.value)}
              />
              <button
                className="btn-secondary text-xs mt-2"
                disabled={updating || adminNoteDraft === (selected.adminNote ?? '')}
                onClick={saveAdminNote}
              >
                Save note
              </button>
            </div>
          </div>
        )}
      </Modal>
    </div>
  );
}

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

      <div className="card mb-6">
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

      <ComplianceReport />

      <DailyReport />
    </div>
  );
}

// The report an auditor asks for, which neither the channel chart nor the
// daily digest can answer: "every PCI-DSS event this period, and what was
// done about it." Grouped by the compliance rule the violated policy carries,
// not by channel or severity.
function ComplianceReport() {
  const [from, setFrom]       = useState(() => {
    const d = new Date();
    d.setDate(d.getDate() - 30);
    return d.toISOString().slice(0, 10);
  });
  const [to, setTo]           = useState(todayStr());
  const [data, setData]       = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError]     = useState('');
  const [expanded, setExpanded] = useState(null);

  const load = async (f, t) => {
    setLoading(true);
    setError('');
    try {
      const { data } = await api.get(`/api/reports/compliance?from=${f}&to=${t}`);
      setData(data);
    } catch (e) {
      setError(e.response?.data?.error ?? 'Could not load the compliance report');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { load(from, to); }, []);   // eslint-disable-line react-hooks/exhaustive-deps

  const apply = () => load(from, to);

  const exportCsv = () => {
    if (!data) return;
    // Auditors work in spreadsheets. Built client-side from data already on
    // the page rather than adding an export endpoint that would re-run the
    // whole query for a format the browser can produce.
    const header = ['Rule', 'Total', 'Incidents', 'AI leak attempts', 'Blocked', 'Allowed',
                    'Critical', 'High', 'Medium', 'Low', 'Reviews requested', 'Awaiting admin', 'Policy enabled'];
    const rows = data.rules.map(g => [
      g.rule, g.total, g.incidents, g.aiLeakAttempts, g.blocked, g.allowed,
      g.bySeverity.CRITICAL, g.bySeverity.HIGH, g.bySeverity.MEDIUM, g.bySeverity.LOW,
      g.reviewRequested, g.awaitingAdmin, g.policyEnabled ? 'yes' : 'NO',
    ]);
    const csv = [header, ...rows]
      .map(r => r.map(c => `"${String(c).replace(/"/g, '""')}"`).join(','))
      .join('\r\n');

    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `dlp-compliance-${from}_to_${to}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="card mb-6">
      <div className="flex flex-wrap items-end justify-between gap-3 mb-4">
        <div>
          <h3 className="text-sm font-semibold text-ink mb-1">Compliance summary</h3>
          <p className="text-xs text-ink-faint">
            Events grouped by the regulation their policy enforces
          </p>
        </div>
        <div className="flex items-end gap-2">
          <label className="flex flex-col gap-1">
            <span className="text-[10px] text-ink-faint uppercase tracking-wider">From</span>
            <input type="date" value={from} onChange={e => setFrom(e.target.value)} className="select" />
          </label>
          <label className="flex flex-col gap-1">
            <span className="text-[10px] text-ink-faint uppercase tracking-wider">To</span>
            <input type="date" value={to} onChange={e => setTo(e.target.value)} className="select" />
          </label>
          <button onClick={apply} className="btn-secondary text-xs">Apply</button>
          <button onClick={exportCsv} disabled={!data?.rules?.length} className="btn-secondary text-xs">
            Export CSV
          </button>
        </div>
      </div>

      {error && <p className="text-xs text-severity-critical-text mb-3">{error}</p>}

      {loading ? (
        <div className="flex justify-center py-10"><Spinner /></div>
      ) : !data || data.rules.length === 0 ? (
        <EmptyState
          icon={ClipboardList}
          title="No compliance policies configured"
          sub="Rules appear here once a policy declares a complianceRule in its conditions."
        />
      ) : (
        <>
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-4">
            <StatCard icon={ClipboardList} label="Events" value={data.summary.totalEvents} />
            <StatCard icon={ShieldX} label="Rules with activity" value={data.summary.rulesWithActivity} tone="critical" />
            <StatCard icon={CheckCircle2} label="Rules covered" value={data.summary.rulesCovered} tone="low" />
            <StatCard icon={Flag} label="Awaiting admin" value={data.summary.awaitingAdmin} tone="medium" />
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead>
                <tr className="border-b border-border">
                  <th className="th">Regulation</th>
                  <th className="th text-right">Events</th>
                  <th className="th text-right">Blocked</th>
                  <th className="th">Severity</th>
                  <th className="th text-right">Awaiting</th>
                  <th className="th" />
                </tr>
              </thead>
              <tbody>
                {data.rules.map(g => (
                  <Fragment key={g.rule}>
                    <tr className="table-row">
                      <td className="td">
                        <span className="font-medium text-ink">{g.rule}</span>
                        {/* Zero events because nothing happened is a very
                            different finding from zero because nothing was
                            watching. */}
                        {!g.policyEnabled && (
                          <span className="badge text-[10px] ml-2 bg-severity-high-soft text-severity-high-text">
                            policy disabled
                          </span>
                        )}
                      </td>
                      <td className="td text-right tabular-nums text-ink">{g.total}</td>
                      <td className="td text-right tabular-nums text-ink-soft">
                        {g.blocked}<span className="text-ink-faint"> / {g.total}</span>
                      </td>
                      <td className="td">
                        <div className="flex items-center gap-1">
                          {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(s => (
                            g.bySeverity[s] > 0 && (
                              <span key={s} className="text-[10px] tabular-nums px-1.5 py-0.5 rounded"
                                    style={{ color: SEVERITY_HEX[s], background: `${SEVERITY_HEX[s]}22` }}>
                                {g.bySeverity[s]} {s[0]}
                              </span>
                            )
                          ))}
                          {g.total === 0 && <span className="text-[11px] text-ink-faint">no events</span>}
                        </div>
                      </td>
                      <td className="td text-right tabular-nums">
                        {g.awaitingAdmin > 0
                          ? <span className="text-severity-high-text">{g.awaitingAdmin}</span>
                          : <span className="text-ink-faint">0</span>}
                      </td>
                      <td className="td text-right">
                        {g.events.length > 0 && (
                          <button
                            onClick={() => setExpanded(expanded === g.rule ? null : g.rule)}
                            className="text-xs text-ink-soft hover:text-ink underline underline-offset-2"
                          >
                            {expanded === g.rule ? 'Hide' : 'Details'}
                          </button>
                        )}
                      </td>
                    </tr>
                    {expanded === g.rule && (
                      <tr>
                        <td colSpan={6} className="px-4 pb-4">
                          <div className="rounded-lg border border-border overflow-hidden">
                            <table className="w-full text-left text-xs">
                              <thead>
                                <tr className="bg-surface-elevated/50">
                                  <th className="th text-[10px]">When</th>
                                  <th className="th text-[10px]">Kind</th>
                                  <th className="th text-[10px]">Channel</th>
                                  <th className="th text-[10px]">Endpoint</th>
                                  <th className="th text-[10px]">Status</th>
                                </tr>
                              </thead>
                              <tbody>
                                {g.events.slice(0, 25).map(e => (
                                  <tr key={e.id} className="border-t border-border">
                                    <td className="td text-ink-faint">{formatDate(e.time)}</td>
                                    <td className="td text-ink-soft">
                                      {e.kind === 'AI_LEAK_ATTEMPT' ? 'AI leak' : 'Incident'}
                                    </td>
                                    <td className="td text-ink-soft">
                                      {PLATFORM_LABELS[e.channel] ?? e.channel}
                                    </td>
                                    <td className="td text-ink-faint">{e.hostname ?? '—'}</td>
                                    <td className="td text-ink-soft">{e.status}</td>
                                  </tr>
                                ))}
                              </tbody>
                            </table>
                            {g.events.length > 25 && (
                              <p className="text-[11px] text-ink-faint px-3 py-2">
                                Showing 25 of {g.events.length}. Export CSV for the full set.
                              </p>
                            )}
                          </div>
                        </td>
                      </tr>
                    )}
                  </Fragment>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}
    </div>
  );
}
