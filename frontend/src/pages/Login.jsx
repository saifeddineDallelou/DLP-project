import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { ShieldCheck, Eye, EyeOff, AlertCircle } from 'lucide-react';
import { useAuth } from '../context/AuthContext.jsx';

export default function Login() {
  const { login } = useAuth();
  const navigate = useNavigate();
  const [email, setEmail]       = useState('');
  const [password, setPassword] = useState('');
  const [showPw, setShowPw]     = useState(false);
  const [error, setError]       = useState('');
  const [loading, setLoading]   = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);
    try {
      await login(email, password);
      navigate('/dashboard', { replace: true });
    } catch (err) {
      if (!err.response) {
        setError('Cannot reach the server. Make sure the backend is running on port 3001.');
      } else {
        setError(err.response.data?.error ?? 'Authentication failed');
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-surface flex items-center justify-center p-4 relative overflow-hidden">
      <div className="absolute inset-0 overflow-hidden pointer-events-none">
        <div className="absolute -top-40 -left-40 w-96 h-96 bg-accent/10 rounded-full blur-3xl" />
        <div className="absolute -bottom-40 -right-40 w-96 h-96 bg-severity-medium/10 rounded-full blur-3xl" />
      </div>

      <div className="relative w-full max-w-sm">
        <div className="flex flex-col items-center mb-8">
          <div className="w-14 h-14 rounded-2xl bg-accent flex items-center justify-center mb-4 shadow-[0_8px_28px_-6px_rgba(53,183,190,0.5)]">
            <ShieldCheck size={28} className="text-[#04191b]" strokeWidth={2.4} />
          </div>
          <h1 className="text-2xl font-bold text-ink">DLP Console</h1>
          <p className="text-ink-faint text-sm mt-1">Data Loss Prevention Platform</p>
        </div>

        <div className="bg-surface-raised border border-border rounded-2xl p-7 shadow-elevated">
          <h2 className="text-base font-semibold text-ink mb-5">Sign in to your account</h2>

          {error && (
            <div className="flex items-center gap-2 bg-severity-critical-soft border border-severity-critical/25
                            text-severity-critical-text text-sm rounded-lg px-3 py-2.5 mb-4">
              <AlertCircle size={14} className="shrink-0" />
              {error}
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label className="label">Email address</label>
              <input
                type="email" className="input" placeholder="admin@dlp.local"
                value={email} onChange={(e) => setEmail(e.target.value)} required autoFocus
              />
            </div>

            <div>
              <label className="label">Password</label>
              <div className="relative">
                <input
                  type={showPw ? 'text' : 'password'} className="input pr-10" placeholder="••••••••"
                  value={password} onChange={(e) => setPassword(e.target.value)} required
                />
                <button
                  type="button" onClick={() => setShowPw(!showPw)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-ink-faint hover:text-ink-soft transition-colors"
                >
                  {showPw ? <EyeOff size={15} /> : <Eye size={15} />}
                </button>
              </div>
            </div>

            <button type="submit" disabled={loading} className="btn-primary w-full mt-2 py-2.5">
              {loading ? (
                <span className="inline-block w-4 h-4 border-2 border-[#04191b]/30 border-t-[#04191b] rounded-full animate-spin" />
              ) : 'Sign In'}
            </button>
          </form>
        </div>

        <p className="text-center text-xs text-ink-faint/70 mt-5">
          DLP Platform v1.0 · Security Operations Console
        </p>
      </div>
    </div>
  );
}
