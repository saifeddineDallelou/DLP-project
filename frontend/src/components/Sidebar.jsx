import { NavLink, useNavigate } from 'react-router-dom';
import {
  LayoutDashboard, AlertTriangle, Shield, Monitor,
  BarChart3, Activity, Brain, LogOut, ShieldCheck,
} from 'lucide-react';
import { useAuth } from '../context/AuthContext.jsx';

const NAV = [
  { to: '/dashboard',  label: 'Dashboard',  Icon: LayoutDashboard },
  { to: '/incidents',  label: 'Incidents',  Icon: AlertTriangle    },
  { to: '/policies',   label: 'Policies',   Icon: Shield           },
  { to: '/agents',     label: 'Agents',     Icon: Monitor          },
  { to: '/reports',    label: 'Reports',    Icon: BarChart3        },
  { to: '/ueba',       label: 'UEBA',       Icon: Activity         },
  { to: '/ai-policy',  label: 'AI Policy',  Icon: Brain            },
];

export default function Sidebar() {
  const { user, logout } = useAuth();
  const navigate = useNavigate();

  const handleLogout = () => {
    logout();
    navigate('/login');
  };

  return (
    <aside className="w-60 shrink-0 flex flex-col bg-slate-900 border-r border-slate-800 h-screen sticky top-0">
      {/* Logo */}
      <div className="flex items-center gap-2.5 px-5 py-5 border-b border-slate-800">
        <div className="w-8 h-8 rounded-lg bg-indigo-600 flex items-center justify-center">
          <ShieldCheck className="text-white" size={18} />
        </div>
        <div>
          <span className="font-bold text-white text-sm tracking-wide">DLP</span>
          <span className="font-bold text-indigo-400 text-sm"> Console</span>
        </div>
      </div>

      {/* Nav */}
      <nav className="flex-1 overflow-y-auto py-4 px-3 space-y-0.5">
        <p className="text-[10px] font-semibold text-slate-500 uppercase tracking-wider px-2 mb-2">
          Navigation
        </p>
        {NAV.map(({ to, label, Icon }) => (
          <NavLink
            key={to}
            to={to}
            className={({ isActive }) =>
              `flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-colors ${
                isActive
                  ? 'bg-indigo-600/20 text-indigo-400 border border-indigo-500/20'
                  : 'text-slate-400 hover:text-slate-100 hover:bg-slate-800'
              }`
            }
          >
            <Icon size={16} />
            {label}
          </NavLink>
        ))}
      </nav>

      {/* User */}
      <div className="border-t border-slate-800 p-3">
        <div className="flex items-center gap-3 px-2 py-2 mb-1">
          <div className="w-7 h-7 rounded-full bg-indigo-600 flex items-center justify-center text-xs font-bold text-white">
            {user?.email?.[0]?.toUpperCase() ?? 'U'}
          </div>
          <div className="flex-1 min-w-0">
            <p className="text-xs font-medium text-slate-200 truncate">{user?.email}</p>
            <p className="text-[10px] text-slate-500">{user?.role}</p>
          </div>
        </div>
        <button
          onClick={handleLogout}
          className="flex items-center gap-2 w-full px-3 py-2 rounded-lg text-xs text-slate-400
                     hover:text-red-400 hover:bg-red-500/10 transition-colors"
        >
          <LogOut size={14} />
          Sign out
        </button>
      </div>
    </aside>
  );
}
