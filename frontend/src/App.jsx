import { Routes, Route, Navigate } from 'react-router-dom';
import ProtectedRoute from './components/ProtectedRoute.jsx';
import Layout        from './components/Layout.jsx';
import Login         from './pages/Login.jsx';
import Dashboard     from './pages/Dashboard.jsx';
import Incidents     from './pages/Incidents.jsx';
import Policies      from './pages/Policies.jsx';
import Agents        from './pages/Agents.jsx';
import Reports       from './pages/Reports.jsx';
import UEBA          from './pages/UEBA.jsx';
import AiPolicy      from './pages/AiPolicy.jsx';

function ProtectedLayout({ children }) {
  return (
    <ProtectedRoute>
      <Layout>{children}</Layout>
    </ProtectedRoute>
  );
}

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<Login />} />

      <Route path="/dashboard"  element={<ProtectedLayout><Dashboard /></ProtectedLayout>} />
      <Route path="/incidents"  element={<ProtectedLayout><Incidents /></ProtectedLayout>} />
      <Route path="/policies"   element={<ProtectedLayout><Policies  /></ProtectedLayout>} />
      <Route path="/agents"     element={<ProtectedLayout><Agents    /></ProtectedLayout>} />
      <Route path="/reports"    element={<ProtectedLayout><Reports   /></ProtectedLayout>} />
      <Route path="/ueba"       element={<ProtectedLayout><UEBA      /></ProtectedLayout>} />
      <Route path="/ai-policy"  element={<ProtectedLayout><AiPolicy  /></ProtectedLayout>} />

      {/* Catch-all → dashboard */}
      <Route path="*" element={<Navigate to="/dashboard" replace />} />
    </Routes>
  );
}
