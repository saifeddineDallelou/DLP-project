import { File, Clipboard, Usb, Printer, Camera, Network } from 'lucide-react';

export const CHANNEL_ICON = {
  FILE: File, CLIPBOARD: Clipboard, USB: Usb,
  PRINT: Printer, SCREENSHOT: Camera, NETWORK: Network,
};

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

export function titleCase(str) {
  if (!str) return '';
  return str.toLowerCase().replace(/(^|_|\s)(\w)/g, (_, sep, c) => (sep === '_' ? ' ' : sep) + c.toUpperCase());
}

// ── Tone maps ──────────────────────────────────────────────────────────────
// Every badge/pill in the app reads from one of these instead of inlining
// Tailwind color classes per-page. Keys are the exact backend enum values.

export const SEVERITY_TONES = {
  LOW:      { bg: 'bg-severity-low-soft',      text: 'text-severity-low-text',      dot: 'bg-severity-low'      },
  MEDIUM:   { bg: 'bg-severity-medium-soft',   text: 'text-severity-medium-text',   dot: 'bg-severity-medium'   },
  HIGH:     { bg: 'bg-severity-high-soft',     text: 'text-severity-high-text',     dot: 'bg-severity-high'     },
  CRITICAL: { bg: 'bg-severity-critical-soft', text: 'text-severity-critical-text', dot: 'bg-severity-critical' },
};

export const STATUS_TONES = {
  OPEN:           { bg: 'bg-accent-soft',              text: 'text-accent-text',            dot: 'bg-accent'              },
  IN_PROGRESS:    { bg: 'bg-severity-medium-soft',     text: 'text-severity-medium-text',   dot: 'bg-severity-medium'     },
  RESOLVED:       { bg: 'bg-severity-low-soft',        text: 'text-severity-low-text',      dot: 'bg-severity-low'        },
  FALSE_POSITIVE: { bg: 'bg-white/5',                  text: 'text-ink-faint',              dot: 'bg-ink-faint'           },
  // A sanctioned match. Deliberately quiet: it is auditable, not
  // actionable, and must not read like something awaiting triage.
  ALLOWED:        { bg: 'bg-white/5',                  text: 'text-ink-faint',              dot: 'bg-severity-low'        },
};

export const ACTION_TONES = {
  ALLOW:      { bg: 'bg-severity-low-soft',      text: 'text-severity-low-text'      },
  ALERT:      { bg: 'bg-severity-medium-soft',   text: 'text-severity-medium-text'   },
  BLOCK:      { bg: 'bg-severity-critical-soft', text: 'text-severity-critical-text' },
  QUARANTINE: { bg: 'bg-accent-soft',            text: 'text-accent-text'            },
};

export const AGENT_STATUS_TONES = {
  ACTIVE:   { bg: 'bg-severity-low-soft',    text: 'text-severity-low-text'    },
  INACTIVE: { bg: 'bg-white/5',              text: 'text-ink-faint'            },
  ERROR:    { bg: 'bg-severity-critical-soft', text: 'text-severity-critical-text' },
};

export const BLOCKED_TONES = {
  true:  { bg: 'bg-severity-critical-soft', text: 'text-severity-critical-text' },
  false: { bg: 'bg-severity-medium-soft',   text: 'text-severity-medium-text'   },
};

export const RISK_LEVEL_TONES = {
  LOW:    { text: 'text-severity-low-text',    bar: 'bg-severity-low'    },
  MEDIUM: { text: 'text-severity-medium-text', bar: 'bg-severity-medium' },
  HIGH:   { text: 'text-severity-high-text',   bar: 'bg-severity-high'   },
  // Deliberately neutral, not green. LEARNING means "not observed enough to
  // judge", which is not the same claim as LOW, and colouring it like a clean
  // result would tell an admin a brand-new employee is safe when nobody has
  // watched them work yet.
  LEARNING: { text: 'text-ink-faint',          bar: 'bg-white/15'        },
};

export function riskLevelFor(score) {
  const pct = (score ?? 0) * 100;
  if (pct >= 70) return 'HIGH';
  if (pct >= 40) return 'MEDIUM';
  return 'LOW';
}

export const COMPLIANCE_RULES = ['PCI-DSS', 'HIPAA', 'GDPR', 'INTERNAL'];

export const COMPLIANCE_RULE_LABELS = {
  'PCI-DSS': 'PCI-DSS · Payment cards',
  HIPAA:     'HIPAA · Health information',
  GDPR:      'GDPR · Personal data',
  INTERNAL:  'Internal · Credentials & secrets',
};

export const EVENT_TYPE_LABELS = {
  FILE_ACCESS:        'File access',
  USB_INSERT:         'USB insert',
  CLIPBOARD_COPY:     'Clipboard copy',
  SCREENSHOT:         'Screenshot',
  APP_LAUNCH:         'App launch',
  AFTER_HOURS_ACCESS: 'After-hours access',
  LARGE_FILE_TRANSFER: 'Large file transfer',
};

export const PLATFORM_LABELS = {
  OPENAI_CHATGPT:    'ChatGPT',
  ANTHROPIC_CLAUDE:  'Claude',
  GOOGLE_GEMINI:     'Gemini',
  MICROSOFT_COPILOT: 'Copilot',
  PERPLEXITY:        'Perplexity',
  POE:               'Poe',
  CHARACTER_AI:      'Character.AI',
  MISTRAL:           'Mistral',
  GROK:              'Grok',
  META_AI:           'Meta AI',
  DEEPSEEK:          'DeepSeek',
  HUGGINGFACE:       'HuggingFace',
  YOU_COM:           'You.com',
  PI_AI:             'Pi.ai',
  GROQ:              'Groq',
  COHERE:            'Cohere',
  OTHER_AI:          'Other AI',
};

/**
 * Split a content sample into an Exact Data Match label and the rest.
 *
 * EDM detections arrive as "edm:<set>:<column|row> ..." -- readable, but
 * indistinguishable at a glance from a regex hit, which is the opposite of
 * the point. A regex hit says content LOOKED sensitive; an EDM hit says it
 * WAS one of the organisation's own records. That difference is the strongest
 * signal in an incident queue and it was rendered as an undifferentiated
 * monospace string.
 *
 * Returns { isEdm, setName, text }.
 */
export function parseDetectionSample(sample) {
  const text = String(sample ?? '');
  // Matched anywhere, not only at the start: a drag-drop sample carries
  // the filename first ("DRAG:cards.csv edm:customers:row ...").
  const m = text.match(/edm:([A-Za-z0-9_.-]+):([A-Za-z0-9_.-]+)\s*/i);
  if (!m) return { isEdm: false, setName: null, text };
  return {
    isEdm: true,
    setName: m[1],
    // Drop the machine-readable prefix; the badge carries that meaning now.
    text: (text.slice(0, m.index) + text.slice(m.index + m[0].length)).trim() || text,
  };
}
