import { useEffect, useState } from 'react'
import {
  Activity,
  CheckCircle2,
  CircleX,
  ShieldAlert,
  Menu,
} from 'lucide-react'
import Sidebar from '../components/Sidebar.jsx'
import StatCard from '../components/StatCard.jsx'
import Loading from '../components/Loading.jsx'
import ErrorMessage from '../components/ErrorMessage.jsx'
import UserLoginSummary from '../components/UserLoginSummary.jsx'
import SuspiciousActivityTimeline from '../components/SuspiciousActivityTimeline.jsx'
import { getDashboardStatistics } from '../services/dashboardService.js'
import { getLoginAttempts } from '../services/loginAttemptService.js'
import { getSuspiciousActivities } from '../services/suspiciousActivityService.js'
import '../styles/dashboard.css'
import LoginAttempts from './LoginAttempts.jsx'
import SuspiciousActivity from './SuspiciousActivity.jsx'

function dashboardError(error) {
  const status = error.response?.status
  if (status === 401) return 'Your session has expired. Please sign in again.'
  if (status === 403) return 'You do not have permission to view dashboard statistics.'
  if (status === 429) return 'Too many requests. Please wait before trying again.'
  if (status >= 500) return 'The server is unavailable. Please try again later.'
  return 'Unable to load dashboard statistics.'
}

export default function Dashboard({ username, role, onLogout }) {
  const [statistics, setStatistics] = useState(null)
  const [attempts, setAttempts] = useState([])
  const [activities, setActivities] = useState([])
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(true)
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false)
  const [activeSection, setActiveSection] = useState('dashboard')

  useEffect(() => {
    let active = true

    async function loadDashboard() {
      setLoading(true)
      setError('')
      try {
        const administrator = role === 'ADMIN' || role === 'SUPERADMIN'
        const requests = [
          getDashboardStatistics(),
          getLoginAttempts(),
          administrator
            ? getSuspiciousActivities()
            : Promise.resolve([]),
        ]
        const [result, loginAttempts, suspiciousActivities] =
          await Promise.all(requests)
        if (active) {
          setStatistics(result)
          setAttempts(loginAttempts)
          setActivities(suspiciousActivities)
        }
      } catch (requestError) {
        if (active) setError(dashboardError(requestError))
      } finally {
        if (active) setLoading(false)
      }
    }

    loadDashboard()
    return () => {
      active = false
    }
  }, [role])

  const noActivity = statistics && (
    statistics.totalLoginAttempts === 0
    && statistics.successfulLoginAttempts === 0
    && statistics.failedLoginAttempts === 0
    && statistics.totalSuspiciousActivities === 0
  )

  return (
    <div className="dashboard-layout">
      <button
        type="button"
        className="mobile-menu-button"
        aria-label="Toggle navigation"
        aria-expanded={mobileMenuOpen}
        onClick={() => setMobileMenuOpen((open) => !open)}
      >
        <Menu size={22} />
      </button>

      <div className={mobileMenuOpen ? 'sidebar-wrap open' : 'sidebar-wrap'}>
        <Sidebar
          username={username}
          role={role}
          onLogout={onLogout}
          activeSection={activeSection}
          onNavigate={(section) => {
            setActiveSection(section)
            setMobileMenuOpen(false)
          }}
        />
      </div>
      {mobileMenuOpen && (
        <button
          type="button"
          className="sidebar-backdrop"
          aria-label="Close navigation"
          onClick={() => setMobileMenuOpen(false)}
        />
      )}

      <main className="dashboard-main">
        {activeSection === 'attempts' ? (
          <LoginAttempts />
        ) : activeSection === 'suspicious' ? (
          <SuspiciousActivity />
        ) : (
          <>
            <header className="dashboard-header">
              <div>
                <p>Overview</p>
                <h1>Dashboard</h1>
              </div>
            </header>

            {loading && <Loading label="Loading dashboard statistics..." />}
            {!loading && error && <ErrorMessage message={error} />}
            {!loading && !error && statistics && (
              <>
                {noActivity && (
                  <div className="dashboard-empty" role="status">
                    No login activity has been recorded yet.
                  </div>
                )}
                <section className="stats-grid" aria-label="Login statistics">
                  <StatCard
                    title="Total Login Attempts"
                    value={statistics.totalLoginAttempts}
                    icon={Activity}
                    tone="navy"
                  />
                  <StatCard
                    title="Successful Attempts"
                    value={statistics.successfulLoginAttempts}
                    icon={CheckCircle2}
                    tone="green"
                  />
                  <StatCard
                    title="Failed Attempts"
                    value={statistics.failedLoginAttempts}
                    icon={CircleX}
                    tone="red"
                  />
                  <StatCard
                    title="Suspicious Activities"
                    value={statistics.totalSuspiciousActivities}
                    icon={ShieldAlert}
                    tone="orange"
                  />
                </section>
                <UserLoginSummary attempts={attempts} />
                {(role === 'ADMIN' || role === 'SUPERADMIN') && (
                  <section
                    className="summary-card"
                    aria-labelledby="dashboard-suspicious-heading"
                  >
                    <h2 id="dashboard-suspicious-heading">
                      Recent Suspicious Activity
                    </h2>
                    <SuspiciousActivityTimeline
                      activities={activities.slice(0, 8)}
                    />
                  </section>
                )}
              </>
            )}
          </>
        )}
      </main>
    </div>
  )
}
