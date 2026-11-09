const SESSION_KEY = 'login_activity_monitor_session'

export function getStoredSession() {
  try {
    const value = window.sessionStorage.getItem(SESSION_KEY)
    return value ? JSON.parse(value) : null
  } catch {
    return null
  }
}

export function storeSession(session) {
  window.sessionStorage.setItem(SESSION_KEY, JSON.stringify(session))
}

export function getSessionId() {
  return getStoredSession()?.sessionId ?? null
}

export function clearStoredSession() {
  window.sessionStorage.removeItem(SESSION_KEY)
}
