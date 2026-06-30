import { useEffect, useState } from 'react';
import { Brain, RefreshCw, ShieldX, ShieldCheck } from 'lucide-react';
import api from '../services/api.js';
import { formatDate } from '../utils/format.js';

const PLATFORMS = [
  'OPENAI_CHATGPT', 'ANTHROPIC_CLAUDE', 'GOOGLE_GEMINI', 'MICROSOFT_COPILOT',
  'PERPLEXITY', 'POE', 'CHARACTER_AI', 'MISTRAL', 'GROK', 'META_AI',
  'DEEPSEEK', 'HUGGINGFACE', 'YOU_COM', 'PI_AI', 'GROQ', 'COHERE', 'OTHER_AI',
];

const PLATFORM_LABELS = {
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

const PLATFORM_COLORS = {
  OPENAI_CHATGPT:    'text-emerald-400 bg-emerald-500/10',
  ANTHROPIC_CLAUDE:  'text-violet-400  bg-violet-500/10',
  GOOGLE_GEMINI:     'text-sky-400     bg-sky-500/10',
  MICROSOFT_COPILOT: 'text-blue-400    bg-blue-500/10',
  PERPLEXITY:        'text-orange-400  bg-orange-500/10',
  POE:               'text-amber-400   bg-amber-500/10',
  CHARACTER_AI:      'text-pink-400    bg-pink-500/10',
  MISTRAL:           'text-yellow-400  bg-yellow-500/10',
  GROK:              'text-red-400     bg-red-500/10',
  META_AI:           'text-indigo-400  bg-indigo-500/10',
  DEEPSEEK:          'text-cyan-400    bg-cyan-500/10',
  HUGGINGFACE:       'text-yellow-300  bg-yellow-400/10',
  YOU_COM:           'text-teal-400    bg-teal-500/10',
  PI_AI:             'text-rose-400    bg-rose-500/10',
  GROQ:              'text-purple-400  bg-purple-500/10',
  COHERE:            'text-lime-400    bg-lime-500/10',
  OTHER_AI:          'text-slate-400   bg-slate-500/10',
};

const METHOD_COLORS = {
  CLIPBOARD:  'text-amber-400  bg-amber-500/10',
  SCREENSHOT: 'text-orange-400 bg-orange-500/10',
  BROWSER:    'text-sky-400    bg-sky-500/10',
  EXTENSION:  'text-violet-400 bg-violet-500/10',
};

function RiskBar({ score }) {
  const pct = Math.round((score ?? 0) * 100);
  const color = pct >= 70 ? 'bg-red-500' : pct >= 40 ? 'bg-amber-500' : 'bg-emerald-500';
  const text  = pct >= 70 ? 'text-red-400' : pct >= 40 ? 'text-amber-400' : 'text-emerald-400';
  return (
    <div className="flex items-center gap-2">
      <div className="w-16 h-1.5 bg-slate-700 rounded-full overflow-hidden">
        <div className={`h-full rounded-full ${color}`} style={{ width: `${pct}%` }} />
      </div>
      <span className={`text-xs font-semibold ${text}`}>{pct}%</span>
    </div>
  );
}

export default function AiPolicy() {
  const [attempts, setAttempts] = useState([]);
  const [total, setTotal]       = useState(0);
  const [loading, setLoading]   = useState(true);
  const [filter, setFilter]     = useState('');

  useEffect(() => {
    let cancelled = false;
    async function load() {
      try {
        const { data } = await api.get('/api/ai-policy/attempts?limit=50');
        if (!cancelled) { setAttempts(data.attempts ?? []); setTotal(data.total ?? 0); }
      } catch (e) { console.error(e); }
      finally { if (!cancelled) setLoading(false); }
    }
    load();
    return () => { cancelled = true; };
  }, []);

  const blocked   = attempts.filter(a => a.blocked).length;
  const displayed = filter ? attempts.filter(a => a.platform === filter) : attempts;

  return (
    <div className="p-6 max-w-7xl mx-auto">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-xl font-bold text-slate-100">AI Leak Policy</h1>
          <p className="text-sm text-slate-400 mt-0.5">Generative AI data exfiltration attempts · {total} detected</p>
        </div>
        <button onClick={() => window.location.reload()} className="btn-secondary flex items-center gap-2 text-sm">
          <RefreshCw size={14} />
        </button>
      </div>

      {/* Summary */}
      <div className="grid grid-cols-3 gap-4 mb-5">
        {[
          { label: 'Total Attempts', val: total,            color: 'text-indigo-400', icon: Brain      },
          { label: 'Blocked',        val: blocked,          color: 'text-red-400',    icon: ShieldX    },
          { label: 'Allowed',        val: total - blocked,  color: 'text-amber-400',  icon: ShieldCheck},
        ].map(({ label, val, color, icon: Icon }) => (
          <div key={label} className="card flex items-center gap-3">
            <div className="w-9 h-9 rounded-lg bg-slate-800 flex items-center justify-center">
              <Icon size={16} className={color} />
            </div>
            <div>
              <p className="text-xs text-slate-500">{label}</p>
              <p className={`text-xl font-bold ${color}`}>{val}</p>
            </div>
          </div>
        ))}
      </div>

      <div className="mb-4">
        <select className="select" value={filter} onChange={e => setFilter(e.target.value)}>
          <option value="">All Platforms</option>
          {PLATFORMS.map(p =>
            <option key={p} value={p}>{PLATFORM_LABELS[p] ?? p}</option>
          )}
        </select>
      </div>

      <div className="card p-0 overflow-hidden">
        <table className="w-full text-left">
          <thead>
            <tr className="border-b border-slate-800 bg-slate-900/50">
              <th className="th">Platform</th>
              <th className="th">Method</th>
              <th className="th">Risk</th>
              <th className="th">Blocked</th>
              <th className="th">Agent</th>
              <th className="th">Content Sample</th>
              <th className="th">Time</th>
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr><td colSpan={7} className="text-center py-16">
                <div className="inline-block w-6 h-6 border-2 border-indigo-500 border-t-transparent
                                rounded-full animate-spin" />
              </td></tr>
            ) : displayed.length === 0 ? (
              <tr><td colSpan={7} className="text-center py-16 text-slate-500 text-sm">
                <Brain size={28} className="text-slate-700 mx-auto mb-2" />
                No AI leak attempts detected
              </td></tr>
            ) : displayed.map((att) => (
              <tr key={att.id} className="table-row cursor-default">
                <td className="td">
                  <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-semibold
                                   ${PLATFORM_COLORS[att.platform] ?? 'text-slate-400 bg-slate-500/10'}`}>
                    {PLATFORM_LABELS[att.platform] ?? att.platform}
                  </span>
                </td>
                <td className="td">
                  <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium
                                   ${METHOD_COLORS[att.method] ?? ''}`}>
                    {att.method}
                  </span>
                </td>
                <td className="td"><RiskBar score={att.riskScore} /></td>
                <td className="td">
                  {att.blocked
                    ? <span className="flex items-center gap-1 text-xs text-red-400"><ShieldX size={12}/> Blocked</span>
                    : <span className="flex items-center gap-1 text-xs text-amber-400"><ShieldCheck size={12}/> Allowed</span>
                  }
                </td>
                <td className="td font-mono text-xs text-slate-400">{att.agent?.hostname ?? '—'}</td>
                <td className="td">
                  <span className="text-[10px] text-slate-500 font-mono max-w-[180px] block truncate">
                    {att.contentSample ?? '—'}
                  </span>
                </td>
                <td className="td text-xs text-slate-500">{formatDate(att.timestamp)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
