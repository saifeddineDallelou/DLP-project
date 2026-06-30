export function formatDate(dateStr) {
  if (!dateStr) return '—';
  return new Date(dateStr).toLocaleString('en-US', {
    month: 'short', day: 'numeric', year: 'numeric',
    hour: '2-digit', minute: '2-digit',
  });
}

export function timeAgo(dateStr) {
  if (!dateStr) return 'Never';
  const diff = Date.now() - new Date(dateStr).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return 'Just now';
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  return `${Math.floor(hours / 24)}d ago`;
}

export function truncate(str, n = 8) {
  if (!str) return '—';
  return str.length > n ? str.slice(0, n) + '…' : str;
}

export const SEVERITY_STYLES = {
  LOW:      'bg-emerald-500/10 text-emerald-400 border-emerald-500/20',
  MEDIUM:   'bg-amber-500/10   text-amber-400   border-amber-500/20',
  HIGH:     'bg-orange-500/10  text-orange-400  border-orange-500/20',
  CRITICAL: 'bg-red-500/10     text-red-400     border-red-500/20',
};

export const SEVERITY_DOT = {
  LOW:      'bg-emerald-400',
  MEDIUM:   'bg-amber-400',
  HIGH:     'bg-orange-400',
  CRITICAL: 'bg-red-400',
};

export const STATUS_STYLES = {
  OPEN:           'bg-sky-500/10     text-sky-400     border-sky-500/20',
  IN_PROGRESS:    'bg-violet-500/10  text-violet-400  border-violet-500/20',
  RESOLVED:       'bg-emerald-500/10 text-emerald-400 border-emerald-500/20',
  FALSE_POSITIVE: 'bg-slate-500/10   text-slate-400   border-slate-500/20',
};

export const SEVERITY_CHART_COLORS = {
  LOW: '#34d399', MEDIUM: '#fbbf24', HIGH: '#fb923c', CRITICAL: '#f87171',
};
