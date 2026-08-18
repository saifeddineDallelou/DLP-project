import { ShieldAlert } from 'lucide-react';
import { COMPLIANCE_RULE_LABELS } from '../utils/format.js';

/**
 * Structured, read-only view of a policy's conditions — replaces
 * <pre>{JSON.stringify(conditions)}</pre>. Falls back to a compact raw
 * listing for any fields it doesn't specifically know how to render, so
 * hand-authored conditions never just disappear.
 */
export default function ConditionsSummary({ conditions }) {
  if (!conditions || typeof conditions !== 'object') {
    return <p className="text-xs text-ink-faint italic">No conditions set</p>;
  }

  const { complianceRule, patterns, threshold, ...rest } = conditions;
  const extraEntries = Object.entries(rest);

  return (
    <div className="space-y-2.5">
      {complianceRule && (
        <div className="flex items-center gap-1.5 text-xs">
          <ShieldAlert size={12} className="text-accent-text shrink-0" />
          <span className="text-ink-soft">{COMPLIANCE_RULE_LABELS[complianceRule] ?? complianceRule}</span>
        </div>
      )}

      {Array.isArray(patterns) && patterns.length > 0 && (
        <div className="flex flex-wrap gap-1">
          {patterns.map((p) => (
            <span key={p} className="chip !py-0.5 !px-2 !text-[10px]">{p}</span>
          ))}
        </div>
      )}

      {threshold != null && (
        <p className="text-[11px] text-ink-faint">
          Triggers at <span className="text-ink-soft font-medium">{threshold}+</span> matching detection{threshold === 1 ? '' : 's'}
        </p>
      )}

      {extraEntries.length > 0 && (
        <p className="text-[10px] text-ink-faint font-mono truncate" title={JSON.stringify(rest)}>
          {extraEntries.map(([k, v]) => `${k}: ${JSON.stringify(v)}`).join('  ·  ')}
        </p>
      )}

      {!complianceRule && (!patterns || patterns.length === 0) && threshold == null && extraEntries.length === 0 && (
        <p className="text-xs text-ink-faint italic">No conditions set</p>
      )}
    </div>
  );
}
