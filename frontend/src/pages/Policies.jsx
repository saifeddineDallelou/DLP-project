import { useEffect, useState, useCallback } from 'react';
import { Plus, Pencil, Trash2, Shield, RefreshCw, ChevronRight } from 'lucide-react';
import api from '../services/api.js';
import Modal from '../components/Modal.jsx';
import { SEVERITY_STYLES, formatDate } from '../utils/format.js';

const ACTION_COLORS = {
  ALLOW:      'text-emerald-400 bg-emerald-500/10',
  ALERT:      'text-amber-400   bg-amber-500/10',
  BLOCK:      'text-red-400     bg-red-500/10',
  QUARANTINE: 'text-violet-400  bg-violet-500/10',
};

const EMPTY_FORM = {
  name: '', description: '', conditions: '{"patterns":[],"threshold":1}',
  action: 'ALERT', severity: 'MEDIUM', enabled: true,
};

function Toggle({ checked, onChange }) {
  return (
    <button
      type="button"
      onClick={() => onChange(!checked)}
      className={`relative w-10 h-5 rounded-full transition-colors ${
        checked ? 'bg-indigo-600' : 'bg-slate-700'
      }`}
    >
      <span className={`absolute top-0.5 w-4 h-4 bg-white rounded-full shadow transition-transform ${
        checked ? 'translate-x-5' : 'translate-x-0.5'
      }`} />
    </button>
  );
}

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
      conditions: JSON.stringify(p.conditions, null, 2),
      action: p.action,
      severity: p.severity,
      enabled: p.enabled,
    });
    setFormError('');
    setEditTarget(p);
  };

  const handleSave = async (e) => {
    e.preventDefault();
    let conditions;
    try {
      conditions = JSON.parse(form.conditions);
    } catch {
      setFormError('Conditions must be valid JSON');
      return;
    }
    setSaving(true);
    try {
      const payload = {
        name: form.name, description: form.description || undefined,
        conditions, action: form.action, severity: form.severity, enabled: form.enabled,
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
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-xl font-bold text-slate-100">Policies</h1>
          <p className="text-sm text-slate-400 mt-0.5">{policies.length} DLP policies defined</p>
        </div>
        <div className="flex gap-2">
          <button onClick={fetchPolicies} className="btn-secondary flex items-center gap-2 text-sm">
            <RefreshCw size={14} />
          </button>
          <button onClick={openCreate} className="btn-primary flex items-center gap-2 text-sm">
            <Plus size={14} /> New Policy
          </button>
        </div>
      </div>

      {loading ? (
        <div className="flex justify-center py-16">
          <div className="w-6 h-6 border-2 border-indigo-500 border-t-transparent rounded-full animate-spin" />
        </div>
      ) : policies.length === 0 ? (
        <div className="card text-center py-16">
          <Shield size={32} className="text-slate-700 mx-auto mb-3" />
          <p className="text-slate-500 text-sm">No policies yet</p>
          <button onClick={openCreate} className="btn-primary mt-4 text-sm">Create first policy</button>
        </div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-2 xl:grid-cols-3 gap-4">
          {policies.map((p) => (
            <div key={p.id} className="card group flex flex-col gap-3">
              <div className="flex items-start justify-between gap-2">
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-1">
                    <span className={`text-[10px] font-bold px-2 py-0.5 rounded ${ACTION_COLORS[p.action] ?? ''}`}>
                      {p.action}
                    </span>
                    <span className={`text-[10px] font-medium px-2 py-0.5 rounded border ${SEVERITY_STYLES[p.severity]}`}>
                      {p.severity}
                    </span>
                    {!p.enabled && (
                      <span className="text-[10px] text-slate-500 bg-slate-800 px-2 py-0.5 rounded">DISABLED</span>
                    )}
                  </div>
                  <h3 className="font-semibold text-slate-100 text-sm truncate">{p.name}</h3>
                  {p.description && (
                    <p className="text-xs text-slate-500 mt-0.5 line-clamp-2">{p.description}</p>
                  )}
                </div>
                <div className="flex gap-1 opacity-0 group-hover:opacity-100 transition-opacity shrink-0">
                  <button
                    onClick={() => openEdit(p)}
                    className="p-1.5 rounded-lg text-slate-500 hover:text-indigo-400 hover:bg-indigo-500/10 transition-colors"
                  >
                    <Pencil size={13} />
                  </button>
                  <button
                    onClick={() => setDeleteTarget(p)}
                    className="p-1.5 rounded-lg text-slate-500 hover:text-red-400 hover:bg-red-500/10 transition-colors"
                  >
                    <Trash2 size={13} />
                  </button>
                </div>
              </div>

              <div className="bg-slate-800/60 rounded-lg p-2.5">
                <p className="text-[10px] text-slate-500 font-medium mb-1">CONDITIONS</p>
                <pre className="text-[10px] text-slate-400 overflow-hidden max-h-16 font-mono">
                  {JSON.stringify(p.conditions, null, 2)}
                </pre>
              </div>

              <div className="flex items-center justify-between text-[10px] text-slate-600 pt-1 border-t border-slate-800">
                <span>v{p.version}</span>
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
      >
        <form onSubmit={handleSave} className="space-y-4">
          {formError && (
            <div className="text-xs text-red-400 bg-red-500/10 border border-red-500/20 rounded-lg px-3 py-2">
              {formError}
            </div>
          )}

          <div>
            <label className="block text-xs font-medium text-slate-400 mb-1.5">Name *</label>
            <input className="input" value={form.name}
              onChange={e => setForm(f => ({ ...f, name: e.target.value }))} required />
          </div>

          <div>
            <label className="block text-xs font-medium text-slate-400 mb-1.5">Description</label>
            <textarea className="input resize-none" rows={2} value={form.description}
              onChange={e => setForm(f => ({ ...f, description: e.target.value }))} />
          </div>

          <div>
            <label className="block text-xs font-medium text-slate-400 mb-1.5">Conditions (JSON) *</label>
            <textarea className="input font-mono text-xs resize-none" rows={4}
              value={form.conditions}
              onChange={e => setForm(f => ({ ...f, conditions: e.target.value }))} required />
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-xs font-medium text-slate-400 mb-1.5">Action</label>
              <select className="select w-full" value={form.action}
                onChange={e => setForm(f => ({ ...f, action: e.target.value }))}>
                {['ALLOW','ALERT','BLOCK','QUARANTINE'].map(a => <option key={a}>{a}</option>)}
              </select>
            </div>
            <div>
              <label className="block text-xs font-medium text-slate-400 mb-1.5">Severity</label>
              <select className="select w-full" value={form.severity}
                onChange={e => setForm(f => ({ ...f, severity: e.target.value }))}>
                {['LOW','MEDIUM','HIGH','CRITICAL'].map(s => <option key={s}>{s}</option>)}
              </select>
            </div>
          </div>

          <div className="flex items-center justify-between py-2">
            <span className="text-xs font-medium text-slate-400">Enabled</span>
            <Toggle
              checked={form.enabled}
              onChange={v => setForm(f => ({ ...f, enabled: v }))}
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
          <p className="text-sm text-slate-300">
            Are you sure you want to delete <strong className="text-white">{deleteTarget?.name}</strong>?
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
