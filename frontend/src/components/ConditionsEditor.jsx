import { useState } from 'react';
import { X, Plus } from 'lucide-react';
import { COMPLIANCE_RULES, COMPLIANCE_RULE_LABELS } from '../utils/format.js';

/**
 * Structured editor for a policy's `conditions` JSON — replaces a raw JSON
 * textarea. Works directly with the parsed object (not a JSON string), so
 * there's no "must be valid JSON" failure mode: the UI can't produce
 * malformed conditions in the first place.
 *
 * Conditions can carry fields this editor doesn't know about (a policy
 * created by hand, or by a future feature) — those are preserved in `_extra`
 * and merged back in unchanged rather than silently dropped.
 */
export default function ConditionsEditor({ value, onChange }) {
  const [patternDraft, setPatternDraft] = useState('');

  const complianceRule = value.complianceRule ?? '';
  const patterns = Array.isArray(value.patterns) ? value.patterns : [];
  const threshold = value.threshold ?? '';

  const update = (patch) => onChange({ ...value, ...patch });

  const addPattern = () => {
    const p = patternDraft.trim().toUpperCase();
    if (!p || patterns.includes(p)) { setPatternDraft(''); return; }
    update({ patterns: [...patterns, p] });
    setPatternDraft('');
  };

  const removePattern = (p) => update({ patterns: patterns.filter((x) => x !== p) });

  return (
    <div className="space-y-4">
      <div>
        <label className="label">Compliance rule</label>
        <select
          className="select w-full"
          value={complianceRule}
          onChange={(e) => update({ complianceRule: e.target.value || undefined })}
        >
          <option value="">No specific rule (general policy)</option>
          {COMPLIANCE_RULES.map((r) => (
            <option key={r} value={r}>{COMPLIANCE_RULE_LABELS[r]}</option>
          ))}
        </select>
        <p className="text-xs text-ink-faint mt-1.5">
          Determines which policy an incident links to — the agent matches this against the
          classifier's detection tag for whatever triggered it.
        </p>
      </div>

      <div>
        <label className="label">Detection patterns</label>
        <div className="flex flex-wrap gap-1.5 mb-2 empty:mb-0">
          {patterns.map((p) => (
            <span key={p} className="chip">
              {p}
              <button
                type="button"
                onClick={() => removePattern(p)}
                className="text-ink-faint hover:text-severity-critical-text transition-colors"
                aria-label={`Remove ${p}`}
              >
                <X size={12} />
              </button>
            </span>
          ))}
        </div>
        <div className="flex gap-2">
          <input
            className="input"
            placeholder="e.g. CREDIT_CARD, SSN, IBAN…"
            value={patternDraft}
            onChange={(e) => setPatternDraft(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Enter' || e.key === ',') { e.preventDefault(); addPattern(); }
            }}
          />
          <button type="button" onClick={addPattern} className="btn-secondary px-3" aria-label="Add pattern">
            <Plus size={15} />
          </button>
        </div>
        <p className="text-xs text-ink-faint mt-1.5">Press Enter or comma to add each pattern.</p>
      </div>

      <div>
        <label className="label">Match threshold</label>
        <input
          type="number"
          min={1}
          className="input"
          style={{ maxWidth: 120 }}
          placeholder="1"
          value={threshold}
          onChange={(e) => update({ threshold: e.target.value === '' ? undefined : Number(e.target.value) })}
        />
        <p className="text-xs text-ink-faint mt-1.5">Minimum number of matching detections before this policy applies.</p>
      </div>
    </div>
  );
}
