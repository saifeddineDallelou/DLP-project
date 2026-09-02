const TONE_CLS = {
  accent:   'bg-accent-soft text-accent-text',
  low:      'bg-severity-low-soft text-severity-low-text',
  medium:   'bg-severity-medium-soft text-severity-medium-text',
  high:     'bg-severity-high-soft text-severity-high-text',
  critical: 'bg-severity-critical-soft text-severity-critical-text',
  neutral:  'bg-white/5 text-ink-soft',
};

/**
 * The one stat-tile component for the whole app. Encodes state in form
 * (icon chip color) as well as number, so severity/status reads at a glance
 * even before the value is parsed.
 */
export default function StatCard({ icon: Icon, label, value, sub, tone = 'accent' }) {
  return (
    <div className="card flex items-center gap-4">
      {/* `icon` is optional. Rendering <Icon /> unconditionally meant a
          caller that omitted it threw "Element type is invalid" and took the
          entire page down with it -- which is exactly what the Compliance
          Report tab did. A stat tile is not worth a white screen. */}
      {Icon && (
        <div className={`w-11 h-11 rounded-xl flex items-center justify-center shrink-0 ${TONE_CLS[tone] ?? TONE_CLS.accent}`}>
          <Icon size={19} />
        </div>
      )}
      <div className="flex-1 min-w-0">
        <p className="text-xs text-ink-faint font-medium mb-0.5">{label}</p>
        <p className="text-2xl font-bold text-ink tabular-nums leading-tight">{value ?? '—'}</p>
        {sub && <p className="text-xs text-ink-faint mt-0.5">{sub}</p>}
      </div>
    </div>
  );
}
