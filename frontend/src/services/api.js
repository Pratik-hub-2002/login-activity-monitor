import axios from 'axios'
import { clearStoredSession, getSessionId } from './authStorage.js'

export const api = axios.create({
  baseURL: import.meta.env.VITE_API_BASE_URL || '/api',
  timeout: 15000,
  headers: {
    Accept: 'application/json',
  },
})

api.interceptors.request.use((config) => {
  const sessionId = getSessionId()
  if (sessionId) {
    config.headers['X-Session-Id'] = sessionId
  }
  return config
})

api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401 && getSessionId()) {
      clearStoredSession()
      window.dispatchEvent(new Event('session-expired'))
    }
    return Promise.reject(error)
  },
)
