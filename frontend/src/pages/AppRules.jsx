import { useEffect, useState, useCallback } from 'react';
import { Plus, Pencil, Trash2, AppWindow, RefreshCw } from 'lucide-react';
import api from '../services/api.js';
import Modal from '../components/Modal.jsx';
import Toggle from '../components/Toggle.jsx';
import PageHeader from '../components/PageHeader.jsx';
import EmptyState from '../components/EmptyState.jsx';
import Spinner from '../components/Spinner.jsx';
import { formatDate } from '../utils/format.js';

const EMPTY_FORM = { keyword: '', label: '', enabled: true };

export default function AppRules() {
  const [rules, setRules]           = useState([]);
  const [loading, setLoading]       = useState(true);
  const [editTarget, setEditTarget] = useState(null);   // null=closed, {}=new, {id}=edit
  const [deleteTarget, setDeleteTarget] = useState(null);
  const [form, setForm]             = useState(EMPTY_FORM);
  const [formError, setFormError]   = useState('');
  const [saving, setSaving]         = useState(false);
  const [deleting, setDeleting]     = useState(false);

  const fetchRules = useCallback(async () => {
    setLoading(true);
    try {
      const { data } = await api.get('/api/app-rules');
      setRules(data);
    } catch (e) { console.error(e); }
    finally { setLoading(false); }
  }, []);

  useEffect(() => { fetchRules(); }, [fetchRules]);

  const openCreate = () => {
    setForm(EMPTY_FORM);
    setFormError('');
    setEditTarget({});
  };

  const openEdit = (r) => {
    setForm({ keyword: r.keyword, label: r.label, enabled: r.enabled });
    setFormError('');
    setEditTarget(r);
  };

  const handleSave = async (e) => {
    e.preventDefault();
    if (!form.keyword.trim() || !form.label.trim()) {
      setFormError('Keyword and label are both required');
      return;
    }
    setSaving(true);
    setFormError('');
    try {
      if (editTarget?.id) {
        await api.put(`/api/app-rules/${editTarget.id}`, form);
      } else {
        await api.post('/api/app-rules', form);
      }
      setEditTarget(null);
      fetchRules();
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
      await api.delete(`/api/app-rules/${deleteTarget.id}`);
      setDeleteTarget(null);
      fetchRules();
    } catch (e) { console.error(e); }
    finally { setDeleting(false); }
  };

  const toggleEnabled = async (r) => {
    try {
      await api.put(`/api/app-rules/${r.id}`, { enabled: !r.enabled });
      fetchRules();
    } catch (e) { console.error(e); }
  };

  return (
    <div className="p-6 max-w-5xl mx-auto">
      <PageHeader
        title="Restricted Apps"
        sub={`${rules.length} rule${rules.length === 1 ? '' : 's'} · flagged when sensitive content is touched while one of these is active — never blocks the app from opening`}
      >
        <button onClick={fetchRules} className="btn-secondary">
          <RefreshCw size={14} />
        </button>
        <button onClick={openCreate} className="btn-primary">
          <Plus size={14} /> New Rule
        </button>
      </PageHeader>

      {loading ? (
        <div className="flex justify-center py-16"><Spinner /></div>
      ) : rules.length === 0 ? (
        <div className="card">
          <EmptyState
            icon={AppWindow}
            title="No restricted-app rules yet"
            sub="Add a keyword (matched against a window title or process name) to flag it as a risky destination for sensitive content."
            action={<button onClick={openCreate} className="btn-primary">Create first rule</button>}
          />
        </div>
      ) : (
        <div className="card p-0 overflow-hidden">
          <table className="w-full text-left">
            <thead>
              <tr className="border-b border-border bg-surface-elevated/50">
                <th className="th">Keyword</th>
                <th className="th">Label</th>
                <th className="th">Enabled</th>
                <th className="th">Updated</th>
                <th className="th"></th>
              </tr>
            </thead>
            <tbody>
              {rules.map((r) => (
                <tr key={r.id} className="table-row group">
                  <td className="td font-mono text-xs text-ink">{r.keyword}</td>
                  <td className="td text-sm text-ink-soft">{r.label}</td>
                  <td className="td">
                    <Toggle checked={r.enabled} onChange={() => toggleEnabled(r)} label={`${r.label} enabled`} />
                  </td>
                  <td className="td text-xs text-ink-faint">{formatDate(r.updatedAt)}</td>
                  <td className="td">
                    <div className="flex gap-1 opacity-0 group-hover:opacity-100 transition-opacity justify-end">
                      <button onClick={() => openEdit(r)} className="btn-icon hover:text-accent-text hover:bg-accent-soft">
                        <Pencil size={13} />
                      </button>
                      <button onClick={() => setDeleteTarget(r)} className="btn-icon hover:text-severity-critical-text hover:bg-severity-critical-soft">
                        <Trash2 size={13} />
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Create / Edit Modal */}
      <Modal
        open={editTarget !== null}
        onClose={() => setEditTarget(null)}
        title={editTarget?.id ? 'Edit Rule' : 'New Rule'}
        maxWidth="max-w-sm"
      >
        <form onSubmit={handleSave} className="space-y-5">
          {formError && (
            <div className="text-xs text-severity-critical-text bg-severity-critical-soft border border-severity-critical/25 rounded-lg px-3 py-2">
              {formError}
            </div>
          )}

          <div>
            <label className="label">Keyword *</label>
            <input className="input" placeholder="e.g. teamviewer" value={form.keyword}
              onChange={e => setForm(f => ({ ...f, keyword: e.target.value }))} required />
            <p className="text-xs text-ink-faint mt-1.5">
              Matched as a substring of the window title / process name, case-insensitive.
            </p>
          </div>

          <div>
            <label className="label">Label *</label>
            <input className="input" placeholder="e.g. TeamViewer remote access" value={form.label}
              onChange={e => setForm(f => ({ ...f, label: e.target.value }))} required />
          </div>

          <div className="flex items-center justify-between py-1">
            <span className="text-sm font-medium text-ink-soft">Enabled</span>
            <Toggle checked={form.enabled} onChange={v => setForm(f => ({ ...f, enabled: v }))} label="Rule enabled" />
          </div>

          <div className="flex gap-3 pt-2">
            <button type="button" className="btn-secondary flex-1" onClick={() => setEditTarget(null)}>
              Cancel
            </button>
            <button type="submit" className="btn-primary flex-1" disabled={saving}>
              {saving ? 'Saving…' : editTarget?.id ? 'Save Changes' : 'Create Rule'}
            </button>
          </div>
        </form>
      </Modal>

      {/* Delete Confirm */}
      <Modal open={!!deleteTarget} onClose={() => setDeleteTarget(null)} title="Delete Rule" maxWidth="max-w-sm">
        <div className="space-y-4">
          <p className="text-sm text-ink-soft">
            Are you sure you want to delete <strong className="text-ink">{deleteTarget?.label}</strong>?
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
