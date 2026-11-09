export default function UserLoginSummary({ attempts }) {
  const summary = {}

  attempts.forEach((attempt) => {
    const username = attempt.username || '-'
    if (!summary[username]) {
      summary[username] = { username, successful: 0, failed: 0 }
    }
    if (attempt.status === 'SUCCESS') summary[username].successful += 1
    if (attempt.status === 'FAILURE') summary[username].failed += 1
  })

  const rows = Object.values(summary).sort((a, b) =>
    a.username.localeCompare(b.username))

  return (
    <section className="summary-card" aria-labelledby="user-summary-heading">
      <h2 id="user-summary-heading">Login Attempts Per User</h2>
      {rows.length ? (
        <div className="table-scroll">
          <table className="summary-table">
            <thead>
              <tr>
                <th>Username</th>
                <th>Successful</th>
                <th>Failed</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((row) => (
                <tr key={row.username}>
                  <td>{row.username}</td>
                  <td><span className="count-success">{row.successful}</span></td>
                  <td><span className="count-failure">{row.failed}</span></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <div className="attempts-empty compact">No user summary is available.</div>
      )}
    </section>
  )
}
