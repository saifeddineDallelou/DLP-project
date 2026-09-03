import { useEffect, useState, useCallback } from 'react';
import { Plus, Pencil, Trash2, Shield, RefreshCw } from 'lucide-react';
import api from '../services/api.js';
import Modal from '../components/Modal.jsx';
import Toggle from '../components/Toggle.jsx';
import Badge from '../components/Badge.jsx';
import PageHeader from '../components/PageHeader.jsx';
import EmptyState from '../components/EmptyState.jsx';
import Spinner from '../components/Spinner.jsx';
import ConditionsEditor from '../components/ConditionsEditor.jsx';
import ConditionsSummary from '../components/ConditionsSummary.jsx';
import { formatDate } from '../utils/format.js';

const EMPTY_FORM = {
  name: '', description: '', conditions: { patterns: [], threshold: 1 },
  action: 'ALERT', severity: 'MEDIUM', enabled: true, channelActions: {}, tiers: [],
};

// Which responses a channel can actually carry out.
//
// A paste, a drag or a file-picker selection is an action IN FLIGHT: it can
// be stopped. A file already sitting in a watched folder is not doing
// anything, so there is nothing to intercept -- BLOCK there would only write
// an incident while claiming to have blocked something, which is exactly what
// it used to do. Moving the file is the only real response.
const CHANNELS = [
  { key: 'CLIPBOARD',   label: 'Clipboard',        hint: 'Copy/paste into an AI window or restricted app',
    actions: ['ALLOW', 'ALERT', 'BLOCK'] },
  { key: 'FILE_UPLOAD', label: 'File upload',      hint: 'Dragged onto a page, or chosen in a file dialog',
    actions: ['ALLOW', 'ALERT', 'BLOCK'] },
  { key: 'SCREENSHOT',  label: 'Screenshot',       hint: 'Screen capture while sensitive content is visible',
    actions: ['ALLOW', 'ALERT', 'BLOCK'] },
  { key: 'FILE',        label: 'File at rest',     hint: 'Found in a watched folder — nothing in flight to stop',
    actions: ['ALLOW', 'ALERT', 'QUARANTINE'] },
];

export default function Policies() {
  const [policies, setPolicies]     = useState([]);
  const [loading, setLoading]       = useState(true);
  const [editTarget, setEditTarget] = useState(null);   // null=closed, {}=new, {id}=edit
  const [deleteTarget, setDeleteTarget] = useState(null);
  const [form, setForm]             = useState(EMPTY_FORM);
  const [formError, setFormError]   = useState('');
  const [saving, setSaving]         = useState(false);
  const [deleting, setDeleting]     = useState(false);

  const fetchPolicies = useCallback(async () => {
    setLoading(true);
    try {
      const { data } = await api.get('/api/policies');
      setPolicies(data);
    } catch (e) { console.error(e); }
    finally { setLoading(false); }
  }, []);

  useEffect(() => { fetchPolicies(); }, [fetchPolicies]);

  const openCreate = () => {
    setForm(EMPTY_FORM);
    setFormError('');
    setEditTarget({});
  };

  const openEdit = (p) => {
    setForm({
      name: p.name,
      description: p.description ?? '',
      conditions: p.conditions ?? { patterns: [], threshold: 1 },
      action: p.action,
      severity: p.severity,
      enabled: p.enabled,
      channelActions: p.channelActions ?? {},
      tiers: p.tiers ?? [],
    });
    setFormError('');
    setEditTarget(p);
  };

  const handleSave = async (e) => {
    e.preventDefault();
    if (!form.name.trim()) { setFormError('Name is required'); return; }
    setSaving(true);
    setFormError('');
    try {
      const payload = {
        name: form.name, description: form.description || undefined,
        conditions: form.conditions, action: form.action, severity: form.severity, enabled: form.enabled,
        channelActions: form.channelActions,
        tiers: form.tiers,
      };
      if (editTarget?.id) {
        await api.put(`/api/policies/${editTarget.id}`, payload);
      } else {
        await api.post('/api/policies', payload);
      }
      setEditTarget(null);
      fetchPolicies();
    } catch (err) {
      setFormError(err.response?.data?.error ?? 'Save failed');
    } finally {
      setSaving(false);
    }
  };

  const handleDelete = async () => {
    if (!deleteTarget) return;
    setDeleting(true);
    try {
      await api.delete(`/api/policies/${deleteTarget.id}`);
      setDeleteTarget(null);
      fetchPolicies();
    } catch (e) { console.error(e); }
    finally { setDeleting(false); }
  };

  return (
    <div className="p-6 max-w-7xl mx-auto">
      <PageHeader title="Policies" sub={`${policies.length} DLP polic${policies.length === 1 ? 'y' : 'ies'} defined`}>
        <button onClick={fetchPolicies} className="btn-secondary">
          <RefreshCw size={14} />
        </button>
        <button onClick={openCreate} className="btn-primary">
          <Plus size={14} /> New Policy
        </button>
      </PageHeader>

      {loading ? (
        <div className="flex justify-center py-16"><Spinner /></div>
      ) : policies.length === 0 ? (
        <div className="card">
          <EmptyState
            icon={Shield}
            title="No policies yet"
            sub="Policies define what counts as sensitive and what the agent should do about it."
            action={<button onClick={openCreate} className="btn-primary">Create first policy</button>}
          />
        </div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-2 xl:grid-cols-3 gap-4">
          {policies.map((p) => (
            <div key={p.id} className="card group flex flex-col gap-3.5">
              <div className="flex items-start justify-between gap-2">
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-1.5 mb-2 flex-wrap">
                    <Badge tone="action" value={p.action} size="sm" />
                    <Badge tone="severity" value={p.severity} size="sm" />
                    {!p.enabled && (
                      <span className="text-[10px] font-semibold text-ink-faint bg-white/5 px-2 py-0.5 rounded-full">
                        DISABLED
                      </span>
                    )}
                  </div>
                  <h3 className="font-semibold text-ink text-sm truncate">{p.name}</h3>
                  {p.description && (
                    <p className="text-xs text-ink-faint mt-0.5 line-clamp-2">{p.description}</p>
                  )}
                </div>
                <div className="flex gap-1 opacity-0 group-hover:opacity-100 transition-opacity shrink-0">
                  <button onClick={() => openEdit(p)} className="btn-icon hover:text-accent-text hover:bg-accent-soft">
                    <Pencil size={13} />
                  </button>
                  <button onClick={() => setDeleteTarget(p)} className="btn-icon hover:text-severity-critical-text hover:bg-severity-critical-soft">
                    <Trash2 size={13} />
                  </button>
                </div>
              </div>

              <div className="bg-surface-elevated rounded-lg p-3 border border-border">
                <p className="text-[10px] text-ink-faint font-semibold uppercase tracking-wide mb-2">Conditions</p>
                <ConditionsSummary conditions={p.conditions} />
              </div>

              <div className="flex items-center justify-between text-[10px] text-ink-faint pt-1 border-t border-border">
                <span className="tabular-nums">v{p.version}</span>
                <span>{formatDate(p.updatedAt)}</span>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Create / Edit Modal */}
      <Modal
        open={editTarget !== null}
        onClose={() => setEditTarget(null)}
        title={editTarget?.id ? 'Edit Policy' : 'New Policy'}
        maxWidth="max-w-xl"
      >
        <form onSubmit={handleSave} className="space-y-5">
          {formError && (
            <div className="text-xs text-severity-critical-text bg-severity-critical-soft border border-severity-critical/25 rounded-lg px-3 py-2">
              {formError}
            </div>
          )}

          <div>
            <label className="label" htmlFor="policy-name">Name *</label>
            <input id="policy-name" className="input" value={form.name}
              onChange={e => setForm(f => ({ ...f, name: e.target.value }))} required />
          </div>

          <div>
            <label className="label">Description</label>
            <textarea className="input resize-none" rows={2} value={form.description}
              onChange={e => setForm(f => ({ ...f, description: e.target.value }))} />
          </div>

          <div className="border-t border-border pt-4">
            <ConditionsEditor
              value={form.conditions}
              onChange={(conditions) => setForm(f => ({ ...f, conditions }))}
            />
          </div>

          <div className="grid grid-cols-2 gap-3 border-t border-border pt-4">
            <div>
              <label className="label">Action</label>
              <select className="select w-full" value={form.action}
                onChange={e => setForm(f => ({ ...f, action: e.target.value }))}>
                {['ALLOW','ALERT','BLOCK','QUARANTINE'].map(a => <option key={a}>{a}</option>)}
              </select>
            </div>
            <div>
              <label className="label">Severity</label>
              <select className="select w-full" value={form.severity}
                onChange={e => setForm(f => ({ ...f, severity: e.target.value }))}>
                {['LOW','MEDIUM','HIGH','CRITICAL'].map(s => <option key={s}>{s}</option>)}
              </select>
            </div>
          </div>

          <div className="border-t border-border pt-4">
            <p className="label mb-1">Graduated response</p>
            <p className="text-xs text-ink-faint mb-3">
              Higher detection confidence, stronger response. Without a ladder the
              action and severity are fixed regardless of how sure the classifier
              was — which is how an incident ends up reading
              <span className="font-mono"> risk 0.93</span>,
              <span className="font-mono"> CRITICAL</span>,
              <span className="font-mono"> ALLOW</span> all at once. Content below the
              lowest rung produces nothing at all.
            </p>

            {form.tiers.length === 0 ? (
              <button
                type="button"
                className="btn-ghost text-xs"
                onClick={() => setForm(f => ({ ...f, tiers: [
                  { minRisk: 0.9, action: 'QUARANTINE', severity: 'CRITICAL' },
                  { minRisk: 0.7, action: 'ALERT', severity: 'HIGH' },
                ] }))}
              >
                + Use a risk ladder
              </button>
            ) : (
              <div className="space-y-2">
                {[...form.tiers]
                  .sort((a, b) => Number(b.minRisk) - Number(a.minRisk))
                  .map((tier, i) => (
                  <div key={i} className="flex items-center gap-2">
                    <span className="text-[11px] text-ink-faint w-14 shrink-0">risk ≥</span>
                    <input
                      type="number" step="0.05" min="0" max="1"
                      aria-label={`Tier ${i + 1} threshold`}
                      className="input w-20 shrink-0"
                      value={tier.minRisk}
                      onChange={e => setForm(f => {
                        const t = [...f.tiers]; t[i] = { ...t[i], minRisk: Number(e.target.value) };
                        return { ...f, tiers: t };
                      })}
                    />
                    <select
                      aria-label={`Tier ${i + 1} action`}
                      className="select flex-1"
                      value={tier.action}
                      onChange={e => setForm(f => {
                        const t = [...f.tiers]; t[i] = { ...t[i], action: e.target.value };
                        return { ...f, tiers: t };
                      })}
                    >
                      {['ALLOW','ALERT','BLOCK','QUARANTINE'].map(a => <option key={a}>{a}</option>)}
                    </select>
                    <select
                      aria-label={`Tier ${i + 1} severity`}
                      className="select w-32 shrink-0"
                      value={tier.severity ?? ''}
                      onChange={e => setForm(f => {
                        const t = [...f.tiers]; t[i] = { ...t[i], severity: e.target.value || null };
                        return { ...f, tiers: t };
                      })}
                    >
                      <option value="">Severity…</option>
                      {['LOW','MEDIUM','HIGH','CRITICAL'].map(sv => <option key={sv}>{sv}</option>)}
                    </select>
                    <button
                      type="button" aria-label={`Remove tier ${i + 1}`}
                      className="btn-icon hover:text-severity-critical-text shrink-0"
                      onClick={() => setForm(f => ({ ...f, tiers: f.tiers.filter((_, j) => j !== i) }))}
                    >×</button>
                  </div>
                ))}
                <button
                  type="button" className="btn-ghost text-xs"
                  onClick={() => setForm(f => ({ ...f, tiers: [...f.tiers, { minRisk: 0.5, action: 'ALERT', severity: 'MEDIUM' }] }))}
                >+ Add a rung</button>
                <p className="text-[11px] text-ink-faint">
                  A ladder replaces the action and severity above. “Stop it” is carried
                  out the way each channel can — cancelled in flight, or moved if the
                  file is already at rest.
                </p>
              </div>
            )}
          </div>

          <div className="border-t border-border pt-4">
            <p className="label mb-1">Response by channel</p>
            <p className="text-xs text-ink-faint mb-3">
              The default above applies wherever a channel is left on
              <span className="font-mono"> Default</span>. Set one here when the response
              should differ — the same data warrants a different answer depending on
              whether it is moving or sitting still.
            </p>
            <div className="space-y-2">
              {CHANNELS.map(ch => (
                <div key={ch.key} className="flex items-center gap-3">
                  <div className="min-w-0 flex-1">
                    <p className="text-xs text-ink">{ch.label}</p>
                    <p className="text-[11px] text-ink-faint truncate" title={ch.hint}>{ch.hint}</p>
                  </div>
                  <select
                    className="select w-40 shrink-0"
                    aria-label={`${ch.label} action`}
                    value={form.channelActions?.[ch.key] ?? ''}
                    onChange={e => setForm(f => {
                      const next = { ...(f.channelActions ?? {}) };
                      if (e.target.value) next[ch.key] = e.target.value;
                      else delete next[ch.key];
                      return { ...f, channelActions: next };
                    })}
                  >
                    <option value="">Default ({form.action})</option>
                    {ch.actions.map(a => <option key={a} value={a}>{a}</option>)}
                  </select>
                </div>
              ))}
            </div>
          </div>

          <div className="flex items-center justify-between py-1">
            <span className="text-sm font-medium text-ink-soft">Enabled</span>
            <Toggle
              checked={form.enabled}
              onChange={v => setForm(f => ({ ...f, enabled: v }))}
              label="Policy enabled"
            />
          </div>

          <div className="flex gap-3 pt-2">
            <button type="button" className="btn-secondary flex-1" onClick={() => setEditTarget(null)}>
              Cancel
            </button>
            <button type="submit" className="btn-primary flex-1" disabled={saving}>
              {saving ? 'Saving…' : editTarget?.id ? 'Save Changes' : 'Create Policy'}
            </button>
          </div>
        </form>
      </Modal>

      {/* Delete Confirm */}
      <Modal open={!!deleteTarget} onClose={() => setDeleteTarget(null)} title="Delete Policy" maxWidth="max-w-sm">
        <div className="space-y-4">
          <p className="text-sm text-ink-soft">
            Are you sure you want to delete <strong className="text-ink">{deleteTarget?.name}</strong>?
            This action cannot be undone.
          </p>
          <div className="flex gap-3">
            <button className="btn-secondary flex-1" onClick={() => setDeleteTarget(null)}>Cancel</button>
            <button className="btn-danger flex-1" onClick={handleDelete} disabled={deleting}>
              {deleting ? 'Deleting…' : 'Delete'}
            </button>
          </div>
        </div>
      </Modal>
    </div>
  );
}
