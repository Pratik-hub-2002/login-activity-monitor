export default function ErrorMessage({ message }) {
  return (
    <div className="error-state" role="alert">
      {message}
    </div>
  )
}
