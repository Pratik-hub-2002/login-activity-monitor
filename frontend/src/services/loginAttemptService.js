import { api } from './api.js'

export async function getLoginAttempts(filters = {}) {
  const response = await api.get('/login', {
    params: {
      username: filters.username || undefined,
      ip_address: filters.ipAddress || undefined,
      status: filters.status || undefined,
    },
  })
  return response.data
}
