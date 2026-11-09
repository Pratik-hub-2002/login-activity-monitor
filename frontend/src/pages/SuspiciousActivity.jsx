import { useEffect, useState } from 'react'
import SuspiciousActivityTimeline from '../components/SuspiciousActivityTimeline.jsx'
import Loading from '../components/Loading.jsx'
import ErrorMessage from '../components/ErrorMessage.jsx'
import { getSuspiciousActivities } from '../services/suspiciousActivityService.js'
import '../styles/suspicious-activity.css'

function suspiciousError(error) {
  const status = error.response?.status
  if (status === 401) return 'Your session has expired. Please sign in again.'
  if (status === 403) return 'Suspicious activity is available to ADMIN and SUPERADMIN users only.'
  if (status === 429) return 'Too many requests. Please wait before trying again.'
  if (status >= 500) return 'The server is unavailable. Please try again later.'
  return 'Unable to load suspicious activity.'
}

export default function SuspiciousActivity() {
  const [filters, setFilters] = useState({
    username: '',
    ipAddress: '',
    activityType: '',
  })
  const [activities, setActivities] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  useEffect(() => {
    let active = true

    async function loadActivities() {
      setLoading(true)
      setError('')
      try {
        const result = await getSuspiciousActivities(filters)
        if (active) setActivities(result)
      } catch (requestError) {
        if (active) setError(suspiciousError(requestError))
      } finally {
        if (active) setLoading(false)
      }
    }

    loadActivities()
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
          <p>Security alerts</p>
          <h1>Suspicious Activity</h1>
        </div>
      </header>

      <section className="suspicious-filters" aria-label="Suspicious activity filters">
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
          <span>Activity type</span>
          <select
            name="activityType"
            value={filters.activityType}
            onChange={updateFilter}
          >
            <option value="">All activity types</option>
            <option value="MULTIPLE_FAILED_ATTEMPTS_BY_USERNAME">
              Multiple failures by username
            </option>
            <option value="MULTIPLE_FAILED_ATTEMPTS_BY_IP">
              Multiple failures by IP
            </option>
            <option value="SUCCESS_AFTER_MULTIPLE_FAILURES">
              Success after multiple failures
            </option>
          </select>
        </label>
      </section>

      {loading && <Loading label="Loading suspicious activity..." />}
      {!loading && error && <ErrorMessage message={error} />}
      {!loading && !error && (
        <SuspiciousActivityTimeline activities={activities} />
      )}
    </>
  )
}
