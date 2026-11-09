import { useEffect, useState } from 'react'
import './App.css'
import Login from './pages/Login.jsx'
import Dashboard from './pages/Dashboard.jsx'
import { getStoredSession, logout } from './services/authService.js'

function App() {
  const [session, setSession] = useState(() => getStoredSession())
  const [sessionExpired, setSessionExpired] = useState(false)

  useEffect(() => {
    function handleSessionExpired() {
      setSession(null)
      setSessionExpired(true)
    }

    window.addEventListener('session-expired', handleSessionExpired)
    return () => window.removeEventListener('session-expired', handleSessionExpired)
  }, [])

  async function handleLogout() {
    await logout()
    setSession(null)
    setSessionExpired(false)
  }

  if (!session) {
    return (
      <Login
        sessionExpired={sessionExpired}
        onLogin={(authenticatedSession) => {
          setSessionExpired(false)
          setSession(authenticatedSession)
        }}
      />
    )
  }

  return (
    <Dashboard
      username={session.username}
      role={session.role}
      onLogout={handleLogout}
    />
  )
}

export default App
