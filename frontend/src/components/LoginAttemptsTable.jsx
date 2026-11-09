function formatTimestamp(value) {
  if (!value) return '-'
  const date = new Date(value)
  return Number.isNaN(date.getTime())
    ? value
    : date.toLocaleString()
}

export default function LoginAttemptsTable({ attempts }) {
  if (!attempts.length) {
    return (
      <div className="attempts-empty" role="status">
        No login attempts match the current filters.
      </div>
    )
  }

  return (
    <div className="table-scroll">
      <table className="attempts-table">
        <thead>
          <tr>
            <th>Username</th>
            <th>IP Address</th>
            <th>Timestamp</th>
            <th>Status</th>
          </tr>
        </thead>
        <tbody>
          {attempts.map((attempt) => (
            <tr key={attempt.id}>
              <td>{attempt.username || '-'}</td>
              <td>{attempt.ip_address || '-'}</td>
              <td>{formatTimestamp(attempt.timestamp)}</td>
              <td>
                <span className={`status-badge ${attempt.status?.toLowerCase()}`}>
                  {attempt.status}
                </span>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
