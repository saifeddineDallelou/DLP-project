import { useEffect, useState, useCallback } from 'react';
import { Plus, Trash2, Database, RefreshCw, ShieldCheck, Layers } from 'lucide-react';
import api from '../services/api.js';
import Modal from '../components/Modal.jsx';
import PageHeader from '../components/PageHeader.jsx';
import EmptyState from '../components/EmptyState.jsx';
import Spinner from '../components/Spinner.jsx';

// Exact Data Match reference sets.
//
// EDM was previously configurable only over HTTP against the classifier --
// there was no page, no way to upload a customer table, and an EDM hit was
// not labelled as one anywhere in the product. A detection engine nobody can
// point at their own data is a detection engine nobody uses.

const RULES = ['GDPR', 'PCI-DSS', 'HIPAA', 'INTERNAL', 'GDPR/loi-09-08'];

const EMPTY_FORM = { name: '', rule: 'INTERNAL', minFields: 1, csv: '' };

/**
 * Parse pasted CSV into the row objects the classifier indexes.
 *
 * Deliberately parsed in the BROWSER: the rows are real customer records, and
 * this keeps them a single POST that is hashed and discarded rather than a
 * file sitting in an upload directory somewhere. Quoted fields are supported
 * because a customer name containing a comma is not an edge case.
 */
export function parseCsv(text) {
  const lines = String(text ?? '').split(/\r?\n/).filter((l) => l.trim() !== '');
  if (lines.length < 2) {
    throw new Error('Need a header row and at least one data row.');
  }

  const split = (line) => {
    const out = [];
    let cur = '';
    let quoted = false;
    for (let i = 0; i < line.length; i++) {
      const ch = line[i];
      if (quoted) {
        if (ch === '"' && line[i + 1] === '"') { cur += '"'; i++; }
        else if (ch === '"') quoted = false;
        else cur += ch;
      } else if (ch === '"') quoted = true;
      else if (ch === ',') { out.push(cur); cur = ''; }
      else cur += ch;
    }
    out.push(cur);
    return out.map((c) => c.trim());
  };

  const headers = split(lines[0]);
  if (headers.some((h) => h === '')) {
    throw new Error('Every column needs a name in the header row.');
  }
  if (new Set(headers).size !== headers.length) {
    throw new Error('Column names must be unique.');
  }

  return lines.slice(1).map((line) => {
    const cells = split(line);
    const row = {};
    headers.forEach((h, i) => {
      const v = cells[i];
      if (v !== undefined && v !== '') row[h] = v;
    });
    return row;
  }).filter((r) => Object.keys(r).length > 0);
}

function SetCard({ set, onDelete }) {
  const correlated = (set.minFields ?? 1) > 1;
  return (
    <div className="card">
      <div className="flex items-start gap-2.5 mb-3">
        <div className="w-8 h-8 rounded-lg bg-surface-elevated flex items-center justify-center shrink-0">
          <Database size={14} className="text-ink-faint" />
        </div>
        <div className="min-w-0 flex-1">
          <p className="text-sm font-medium text-ink truncate" title={set.name}>{set.name}</p>
          <p className="text-[11px] text-ink-faint">
            {set.rowCount ?? 0} record{set.rowCount === 1 ? '' : 's'} · {set.totalValues} indexed value
            {set.totalValues === 1 ? '' : 's'}
          </p>
        </div>
        <span className="badge text-[10px] bg-white/5 text-ink-soft">{set.rule}</span>
        <button
          onClick={() => onDelete(set)}
          aria-label={`Delete ${set.name}`}
          className="btn-icon hover:text-severity-critical-text hover:bg-severity-critical-soft"
        >
          <Trash2 size={13} />
        </button>
      </div>

      <div className="flex items-center gap-1.5 mb-3">
        <Layers size={11} className={correlated ? 'text-accent-text' : 'text-ink-faint'} />
        <p className="text-[11px] text-ink-soft">
          {correlated
            ? `Correlated — ${set.minFields} fields of one record must match`
            : 'Per-value — any single indexed value matches'}
        </p>
      </div>

      <div className="pt-2 border-t border-border">
        <p className="text-[9px] text-ink-faint uppercase tracking-wide mb-1.5">Indexed columns</p>
        <div className="flex flex-wrap gap-1">
          {Object.entries(set.columns ?? {}).map(([col, n]) => (
            <span key={col} className="badge text-[10px] bg-white/5 text-ink-soft">
              {col} <span className="text-ink-faint">· {n}</span>
            </span>
          ))}
        </div>
      </div>
    </div>
  );
}

export default function ReferenceSets() {
  const [sets, setSets]         = useState([]);
  const [loading, setLoading]   = useState(true);
  const [loadError, setLoadError] = useState('');
  const [creating, setCreating] = useState(false);
  const [deleteTarget, setDeleteTarget] = useState(null);
  const [form, setForm]         = useState(EMPTY_FORM);
  const [formError, setFormError] = useState('');
  const [saving, setSaving]     = useState(false);
  const [deleting, setDeleting] = useState(false);

  const fetchSets = useCallback(async () => {
    setLoading(true);
    setLoadError('');
    try {
      const { data } = await api.get('/api/edm');
      setSets(Array.isArray(data) ? data : []);
    } catch (e) {
      // The classifier being down is a normal operational state, not a crash.
      // Say which service is missing rather than showing an empty page that
      // implies no sets are configured.
      setLoadError(
        e?.response?.status === 503
          ? 'Classifier service unavailable — reference sets cannot be read while it is down.'
          : 'Could not load reference sets.',
      );
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { fetchSets(); }, [fetchSets]);

  const openCreate = () => { setForm(EMPTY_FORM); setFormError(''); setCreating(true); };

  const handleSave = async (e) => {
    e.preventDefault();
    setFormError('');

    if (!form.name.trim()) { setFormError('Give the set a name.'); return; }

    let rows;
    try {
      rows = parseCsv(form.csv);
    } catch (err) {
      setFormError(err.message);
      return;
    }
    if (rows.length === 0) { setFormError('No data rows found.'); return; }

    setSaving(true);
    try {
      await api.post('/api/edm', {
        name: form.name.trim(),
        rule: form.rule,
        min_fields: Number(form.minFields) || 1,
        rows,
      });
      setCreating(false);
      setForm(EMPTY_FORM);      // drop the pasted records from component state
      await fetchSets();
    } catch (err) {
      setFormError(err?.response?.data?.error || 'Could not index the reference set.');
    } finally {
      setSaving(false);
    }
  };

  const handleDelete = async () => {
    setDeleting(true);
    try {
      await api.delete(`/api/edm/${encodeURIComponent(deleteTarget.name)}`);
      setDeleteTarget(null);
      await fetchSets();
    } catch (e) { console.error(e); }
    finally { setDeleting(false); }
  };

  const rowCount = (() => {
    try { return parseCsv(form.csv).length; } catch { return 0; }
  })();

  return (
    <>
      <PageHeader
        title="Reference Sets"
        sub="Exact Data Match — detect your own records, not just data that looks like them"
      >
        <button onClick={fetchSets} className="btn-ghost" aria-label="Refresh">
          <RefreshCw size={14} />
        </button>
        <button onClick={openCreate} className="btn-primary">
          <Plus size={14} /> New Set
        </button>
      </PageHeader>

      {loadError && (
        <div className="card mb-4 text-xs text-severity-critical-text">{loadError}</div>
      )}

      {loading ? (
        <div className="flex justify-center py-16"><Spinner /></div>
      ) : sets.length === 0 && !loadError ? (
        <div className="card">
          <EmptyState
            icon={Database}
            title="No reference sets yet"
            sub="Upload a table of real records — customers, staff, accounts — and content matching them is detected exactly, instead of being guessed at by shape. Only salted hashes are stored."
            action={<button onClick={openCreate} className="btn-primary">Index first set</button>}
          />
        </div>
      ) : (
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
          {sets.map((s) => <SetCard key={s.name} set={s} onDelete={setDeleteTarget} />)}
        </div>
      )}

      <Modal
        open={creating}
        onClose={() => setCreating(false)}
        title="Index a reference set"
        maxWidth="max-w-2xl"
      >
        <form onSubmit={handleSave} className="space-y-5">
          {formError && (
            <div className="text-xs text-severity-critical-text bg-severity-critical-soft border border-severity-critical/25 rounded-lg px-3 py-2">
              {formError}
            </div>
          )}

          {/* Stated up front, because pasting real customer records into a
              form is a reasonable thing to hesitate over. */}
          <div className="flex items-start gap-2 text-[11px] text-ink-soft bg-white/5 border border-border rounded-lg px-3 py-2">
            <ShieldCheck size={13} className="text-accent-text shrink-0 mt-0.5" />
            <p>
              Records are hashed and discarded — only salted digests are stored, never the
              values themselves. Nothing pasted here is written to the database or the audit
              log.
            </p>
          </div>

          <div className="grid grid-cols-3 gap-3">
            <div className="col-span-2">
              <label className="label" htmlFor="edm-name">Set name *</label>
              <input id="edm-name" className="input" placeholder="e.g. customers" value={form.name}
                onChange={e => setForm(f => ({ ...f, name: e.target.value }))} required />
            </div>
            <div>
              <label className="label" htmlFor="edm-rule">Compliance rule</label>
              <select id="edm-rule" className="input" value={form.rule}
                onChange={e => setForm(f => ({ ...f, rule: e.target.value }))}>
                {RULES.map(r => <option key={r} value={r}>{r}</option>)}
              </select>
            </div>
          </div>

          <div>
            <label className="label" htmlFor="edm-min-fields">Fields required to match</label>
            <input id="edm-min-fields" type="number" min="1" max="20" className="input"
              value={form.minFields}
              onChange={e => setForm(f => ({ ...f, minFields: e.target.value }))} />
            <p className="text-xs text-ink-faint mt-1.5">
              {Number(form.minFields) > 1
                ? `A record only matches when ${form.minFields} of its fields appear together. This is what makes a common column — a surname, a city — safe to index.`
                : 'Any single indexed value matches. Use this only for distinctive columns; a common value will fire on unrelated documents.'}
            </p>
          </div>

          <div>
            <label className="label" htmlFor="edm-csv">Records (CSV, with a header row) *</label>
            <textarea
              id="edm-csv"
              className="input font-mono text-xs h-40"
              placeholder={'name,city,account\nSarah Okafor,Manchester,ACC-4472819'}
              value={form.csv}
              onChange={e => setForm(f => ({ ...f, csv: e.target.value }))}
              required
            />
            <p className="text-xs text-ink-faint mt-1.5">
              {rowCount > 0
                ? `${rowCount} record${rowCount === 1 ? '' : 's'} ready to index.`
                : 'Values under 4 characters are skipped — too short to be distinctive.'}
            </p>
          </div>

          <div className="flex justify-end gap-2">
            <button type="button" onClick={() => setCreating(false)} className="btn-ghost">Cancel</button>
            <button type="submit" disabled={saving} className="btn-primary">
              {saving ? 'Indexing…' : 'Index set'}
            </button>
          </div>
        </form>
      </Modal>

      <Modal
        open={deleteTarget !== null}
        onClose={() => setDeleteTarget(null)}
        title="Delete reference set"
        maxWidth="max-w-sm"
      >
        <p className="text-sm text-ink-soft mb-5">
          Delete <span className="text-ink font-medium">{deleteTarget?.name}</span>? Every
          detection it provides stops immediately, and the records would have to be uploaded
          again to restore it.
        </p>
        <div className="flex justify-end gap-2">
          <button onClick={() => setDeleteTarget(null)} className="btn-ghost">Cancel</button>
          <button onClick={handleDelete} disabled={deleting} className="btn-danger">
            {deleting ? 'Deleting…' : 'Delete'}
          </button>
        </div>
      </Modal>
    </>
  );
}
