import { ShieldAlert } from 'lucide-react'

function formatTimestamp(value) {
  if (!value) return '-'
  const date = new Date(value)
  return Number.isNaN(date.getTime())
    ? value
    : date.toLocaleString()
}

function formatActivityType(value) {
  return value?.replaceAll('_', ' ') || 'SUSPICIOUS ACTIVITY'
}

export default function SuspiciousActivityTimeline({ activities }) {
  if (!activities.length) {
    return (
      <div className="suspicious-empty" role="status">
        No suspicious activity matches the current filters.
      </div>
    )
  }

  return (
    <ol className="suspicious-timeline">
      {activities.map((activity) => (
        <li className="timeline-item" key={activity.id}>
          <span className="timeline-marker" aria-hidden="true">
            <ShieldAlert size={18} />
          </span>
          <article className="timeline-card">
            <div className="timeline-heading">
              <span className="activity-type">
                {formatActivityType(activity.activityType)}
              </span>
              <time dateTime={activity.timestamp}>
                {formatTimestamp(activity.timestamp)}
              </time>
            </div>
            <p className="activity-description">{activity.reason}</p>
            <div className="activity-meta">
              <span>
                <strong>IP:</strong> {activity.ip_address || '-'}
              </span>
              {activity.username && (
                <span>
                  <strong>User:</strong> {activity.username}
                </span>
              )}
            </div>
          </article>
        </li>
      ))}
    </ol>
  )
}
