import { NavLink, useNavigate } from 'react-router-dom';
import {
  LayoutDashboard, AlertTriangle, Shield, Monitor,
  BarChart3, Activity, Brain, LogOut, ShieldCheck, AppWindow,
} from 'lucide-react';
import { useAuth } from '../context/AuthContext.jsx';

const NAV_GROUPS = [
  {
    label: 'Overview',
    items: [{ to: '/dashboard', label: 'Dashboard', Icon: LayoutDashboard }],
  },
  {
    label: 'Protection',
    items: [
      { to: '/incidents', label: 'Incidents', Icon: AlertTriangle },
      { to: '/policies',  label: 'Policies',  Icon: Shield },
      { to: '/ai-policy', label: 'AI Policy', Icon: Brain },
      { to: '/app-rules', label: 'Restricted Apps', Icon: AppWindow },
    ],
  },
  {
    label: 'Monitoring',
    items: [
      { to: '/agents', label: 'Agents', Icon: Monitor },
      { to: '/ueba',   label: 'UEBA',   Icon: Activity },
    ],
  },
  {
    label: 'Analytics',
    items: [{ to: '/reports', label: 'Reports', Icon: BarChart3 }],
  },
];

export default function Sidebar() {
  const { user, logout } = useAuth();
  const navigate = useNavigate();

  const handleLogout = () => {
    logout();
    navigate('/login');
  };

  return (
    <aside className="w-64 shrink-0 flex flex-col bg-surface-raised border-r border-border h-screen sticky top-0">
      {/* Logo */}
      <div className="flex items-center gap-2.5 px-5 py-5 border-b border-border">
        <div className="w-8 h-8 rounded-lg bg-accent flex items-center justify-center shadow-[0_0_0_1px_rgba(255,255,255,0.1)_inset]">
          <ShieldCheck className="text-[#04191b]" size={18} strokeWidth={2.4} />
        </div>
        <div className="leading-none">
          <div className="font-bold text-ink text-sm tracking-tight">DLP Console</div>
          <div className="text-[10px] text-ink-faint mt-0.5">Security Operations</div>
        </div>
      </div>

      {/* Nav */}
      <nav className="flex-1 overflow-y-auto py-4 px-3 space-y-5">
        {NAV_GROUPS.map((group) => (
          <div key={group.label}>
            <p className="text-[10px] font-semibold text-ink-faint uppercase tracking-wider px-3 mb-1.5">
              {group.label}
            </p>
            <div className="space-y-0.5">
              {group.items.map(({ to, label, Icon }) => (
                <NavLink
                  key={to}
                  to={to}
                  className={({ isActive }) =>
                    `group flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-colors duration-150 relative ${
                      isActive
                        ? 'bg-accent-soft text-accent-text'
                        : 'text-ink-soft hover:text-ink hover:bg-surface-hover'
                    }`
                  }
                >
                  {({ isActive }) => (
                    <>
                      {isActive && (
                        <span className="absolute left-0 top-1/2 -translate-y-1/2 h-4 w-[3px] rounded-r bg-accent" />
                      )}
                      <Icon size={16} strokeWidth={isActive ? 2.4 : 2} />
                      {label}
                    </>
                  )}
                </NavLink>
              ))}
            </div>
          </div>
        ))}
      </nav>

      {/* User */}
      <div className="border-t border-border p-3">
        <div className="flex items-center gap-3 px-2 py-2 mb-1">
          <div className="w-7 h-7 rounded-full bg-accent-soft flex items-center justify-center text-xs font-bold text-accent-text shrink-0">
            {user?.email?.[0]?.toUpperCase() ?? 'U'}
          </div>
          <div className="flex-1 min-w-0">
            <p className="text-xs font-medium text-ink truncate">{user?.email}</p>
            <p className="text-[10px] text-ink-faint">{user?.role}</p>
          </div>
        </div>
        <button
          onClick={handleLogout}
          className="flex items-center gap-2 w-full px-3 py-2 rounded-lg text-xs text-ink-soft
                     hover:text-severity-critical-text hover:bg-severity-critical-soft transition-colors duration-150"
        >
          <LogOut size={14} />
          Sign out
        </button>
      </div>
    </aside>
  );
}
