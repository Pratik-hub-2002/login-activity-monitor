import { LayoutDashboard, ListChecks, LogOut, ShieldAlert, ShieldCheck } from 'lucide-react'

export default function Sidebar({
  username,
  role,
  onLogout,
  activeSection,
  onNavigate,
}) {
  return (
    <aside className="sidebar">
      <div className="sidebar-brand">
        <ShieldCheck size={26} aria-hidden="true" />
        <span>Login Monitor</span>
      </div>

      <nav className="sidebar-nav" aria-label="Dashboard navigation">
        <button
          type="button"
          className={activeSection === 'dashboard' ? 'sidebar-link active' : 'sidebar-link'}
          aria-current={activeSection === 'dashboard' ? 'page' : undefined}
          onClick={() => onNavigate('dashboard')}
        >
          <LayoutDashboard size={18} aria-hidden="true" />
          <span>Dashboard</span>
        </button>
        <button
          type="button"
          className={activeSection === 'attempts' ? 'sidebar-link active' : 'sidebar-link'}
          aria-current={activeSection === 'attempts' ? 'page' : undefined}
          onClick={() => onNavigate('attempts')}
        >
          <ListChecks size={18} aria-hidden="true" />
          <span>Login Attempts</span>
        </button>
        {(role === 'ADMIN' || role === 'SUPERADMIN') && (
          <button
            type="button"
            className={activeSection === 'suspicious' ? 'sidebar-link active' : 'sidebar-link'}
            aria-current={activeSection === 'suspicious' ? 'page' : undefined}
            onClick={() => onNavigate('suspicious')}
          >
            <ShieldAlert size={18} aria-hidden="true" />
            <span>Suspicious Activity</span>
          </button>
        )}
      </nav>

      <div className="sidebar-user">
        <div className="user-avatar" aria-hidden="true">
          {username.charAt(0).toUpperCase()}
        </div>
        <strong>{username}</strong>
      </div>

      <button type="button" className="sidebar-logout" onClick={onLogout}>
        <LogOut size={18} aria-hidden="true" />
        <span>Logout</span>
      </button>
    </aside>
  )
}
