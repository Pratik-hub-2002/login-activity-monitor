import { useEffect, useState } from 'react'
import LoginAttemptsTable from '../components/LoginAttemptsTable.jsx'
import UserLoginSummary from '../components/UserLoginSummary.jsx'
import Loading from '../components/Loading.jsx'
import ErrorMessage from '../components/ErrorMessage.jsx'
import { getLoginAttempts } from '../services/loginAttemptService.js'
import '../styles/login-attempts.css'

function attemptsError(error) {
  const status = error.response?.status
  if (status === 401) return 'Your session has expired. Please sign in again.'
  if (status === 403) return 'You do not have permission to view these login records.'
  if (status === 429) return 'Too many requests. Please wait before trying again.'
  if (status >= 500) return 'The server is unavailable. Please try again later.'
  return 'Unable to load login attempts.'
}

export default function LoginAttempts() {
  const [filters, setFilters] = useState({
    username: '',
    ipAddress: '',
    status: '',
  })
  const [attempts, setAttempts] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  useEffect(() => {
    let active = true

    async function loadAttempts() {
      setLoading(true)
      setError('')
      try {
        const result = await getLoginAttempts(filters)
        if (active) setAttempts(result)
      } catch (requestError) {
        if (active) setError(attemptsError(requestError))
      } finally {
        if (active) setLoading(false)
      }
    }

    loadAttempts()
    return () => {
      active = false
    }
  }, [filters])

  function updateFilter(event) {
    const { name, value } = event.target
    setFilters((current) => ({ ...current, [name]: value }))
  }

  return (
    <>
      <header className="dashboard-header">
        <div>
          <p>History</p>
          <h1>Login Attempts</h1>
        </div>
      </header>

      <section className="attempts-filters" aria-label="Login attempt filters">
        <label>
          <span>Username</span>
          <input
            name="username"
            value={filters.username}
            onChange={updateFilter}
            placeholder="Filter by username"
          />
        </label>
        <label>
          <span>IP Address</span>
          <input
            name="ipAddress"
            value={filters.ipAddress}
            onChange={updateFilter}
            placeholder="Filter by IP address"
          />
        </label>
        <label>
          <span>Status</span>
          <select name="status" value={filters.status} onChange={updateFilter}>
            <option value="">All statuses</option>
            <option value="SUCCESS">SUCCESS</option>
            <option value="FAILURE">FAILURE</option>
          </select>
        </label>
      </section>

      {loading && <Loading label="Loading login attempts..." />}
      {!loading && error && <ErrorMessage message={error} />}
      {!loading && !error && (
        <>
          <UserLoginSummary attempts={attempts} />
          <section className="attempts-card" aria-labelledby="recent-attempts-heading">
            <h2 id="recent-attempts-heading">Recent Login Attempts</h2>
            <LoginAttemptsTable attempts={attempts} />
          </section>
        </>
      )}
    </>
  )
}
