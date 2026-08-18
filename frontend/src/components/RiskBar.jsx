import { riskLevelFor, RISK_LEVEL_TONES } from '../utils/format.js';

/**
 * The one risk-score progress bar for the whole app — Incidents, AiPolicy,
 * and UEBA all previously defined their own near-identical copy of this.
 */
export default function RiskBar({ score, width = 'w-16' }) {
  if (score == null) return <span className="text-ink-faint text-xs">—</span>;
  const pct = Math.round(score * 100);
  const level = riskLevelFor(score);
  const tone = RISK_LEVEL_TONES[level];

  return (
    <div className="flex items-center gap-2">
      <div className={`${width} h-1.5 bg-surface-elevated rounded-full overflow-hidden`}>
        <div className={`h-full rounded-full ${tone.bar} transition-all duration-300`} style={{ width: `${pct}%` }} />
      </div>
      <span className={`text-xs font-semibold tabular-nums ${tone.text}`}>{pct}%</span>
    </div>
  );
}
