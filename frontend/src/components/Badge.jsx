import {
  SEVERITY_TONES, STATUS_TONES, ACTION_TONES, AGENT_STATUS_TONES, BLOCKED_TONES,
} from '../utils/format.js';

const TONE_MAPS = {
  severity: SEVERITY_TONES,
  status: STATUS_TONES,
  action: ACTION_TONES,
  agentStatus: AGENT_STATUS_TONES,
  blocked: BLOCKED_TONES,
};

/**
 * Reads its color from a shared tone map instead of each page inlining its
 * own Tailwind color strings — one place to keep severity/status/action
 * colors consistent across Incidents, Policies, Agents, AiPolicy, Dashboard.
 */
export default function Badge({ tone, value, label, dot = false, size = 'md', icon: Icon }) {
  const map = TONE_MAPS[tone] ?? {};
  const style = map[value] ?? { bg: 'bg-white/5', text: 'text-ink-faint', dot: 'bg-ink-faint' };
  const text = label ?? (typeof value === 'string' ? value.replace(/_/g, ' ') : String(value));
  const sizeCls = size === 'sm' ? 'text-[10px] px-2 py-0.5' : 'text-xs px-2.5 py-1';

  return (
    <span className={`badge ${sizeCls} ${style.bg} ${style.text}`}>
      {dot && <span className={`w-1.5 h-1.5 rounded-full ${style.dot ?? style.text}`} />}
      {Icon && <Icon size={size === 'sm' ? 11 : 12} />}
      {text}
    </span>
  );
}
