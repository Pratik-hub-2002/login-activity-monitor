import {
  clearStoredSession,
  getStoredSession as readStoredSession,
  storeSession,
} from './authStorage.js'

import { api } from './api.js'

function toBasicAuthorization(username, password) {
  const bytes = new TextEncoder().encode(`${username}:${password}`)
  let binary = ''

  bytes.forEach((byte) => {
    binary += String.fromCharCode(byte)
  })

  return `Basic ${btoa(binary)}`
}

export async function beginLogin(username, password, captchaToken) {
  const headers = {
    Authorization: toBasicAuthorization(username, password),
    Accept: 'application/json',
  }

  if (captchaToken) {
    headers['X-Captcha-Token'] = captchaToken
  }

  const response = await api.post('/auth/login', null, {
    headers,
    timeout: 15000,
  })

  return response.data
}

export async function completeLogin(username, password, otp) {
  const response = await api.post(
    '/auth/otp/verify',
    { otp },
    {
      headers: {
        Authorization: toBasicAuthorization(username, password),
        Accept: 'application/json',
      },
      timeout: 15000,
    }
  )

  const session = {
    sessionId: response.data.session.sessionId,
    username: response.data.loginAttempt.username,
    createdAt: response.data.session.createdAt,
    expiresAt: response.data.session.expiresAt,
    role: response.data.role,
  }

  storeSession(session)

  return session
}

export function getStoredSessionValue() {
  return readStoredSession()
}

export function getStoredSession() {
  return getStoredSessionValue()
}

export async function logout() {
  const session = getStoredSession()

  if (!session?.sessionId) {
    clearStoredSession()
    return
  }

  try {
    await api.post('/auth/logout', null, {
      headers: {
        'X-Session-Id': session.sessionId,
        Accept: 'application/json',
      },
      timeout: 15000,
    })
  } finally {
    clearStoredSession()
  }
}