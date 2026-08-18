const FIELD_LABELS = {
  deviceId: 'Device', volumeLabel: 'Volume', sizeMB: 'Size',
  window_title: 'Window', key: 'Trigger', blocked: 'Blocked',
  process_name: 'Process', pid: 'PID', watch_label: 'Flagged as',
  filesAccessed: 'Files', count: 'Count', hour: 'Hour', note: 'Note',
  timestamp: 'At',
};

function formatValue(key, v) {
  if (v == null) return '—';
  if (key === 'sizeMB') {
    const mb = Number(v);
    return mb >= 1024 ? `${(mb / 1024).toFixed(1)} GB` : `${mb} MB`;
  }
  if (key === 'hour') {
    const h = Number(v);
    const period = h >= 12 ? 'PM' : 'AM';
    const h12 = h % 12 === 0 ? 12 : h % 12;
    return `${h12}:00 ${period}`;
  }
  if (key === 'blocked') return v ? 'Yes' : 'No';
  if (key === 'timestamp') return new Date(v).toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' });
  if (typeof v === 'boolean') return v ? 'Yes' : 'No';
  return String(v);
}

/**
 * Structured, per-field rendering of a behavior event's metadata blob —
 * replaces <pre>{JSON.stringify(metadata)}</pre>. Metadata shape varies by
 * event type (a USB insert carries a device id; a screenshot carries a
 * window title), so this renders whatever keys are actually present rather
 * than assuming one fixed schema.
 */
export default function EventMetadata({ metadata }) {
  if (!metadata || typeof metadata !== 'object' || Object.keys(metadata).length === 0) {
    return <span className="text-ink-faint text-xs">—</span>;
  }

  const entries = Object.entries(metadata).filter(([, v]) => v !== undefined);

  return (
    <div className="flex flex-wrap gap-x-3 gap-y-0.5 max-w-[280px]">
      {entries.map(([k, v]) => (
        <span key={k} className="text-[11px] text-ink-faint whitespace-nowrap">
          <span className="text-ink-faint/70">{FIELD_LABELS[k] ?? k}:</span>{' '}
          <span className="text-ink-soft">{formatValue(k, v)}</span>
        </span>
      ))}
    </div>
  );
}
