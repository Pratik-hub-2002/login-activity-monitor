export default function StatCard({ title, value, icon: Icon, tone = 'navy' }) {
  return (
    <article className={`stat-card stat-card-${tone}`}>
      <div>
        <p>{title}</p>
        <strong>{value.toLocaleString()}</strong>
      </div>
      <span className="stat-icon" aria-hidden="true">
        {Icon ? <Icon size={22} /> : null}
      </span>
    </article>
  )
}
