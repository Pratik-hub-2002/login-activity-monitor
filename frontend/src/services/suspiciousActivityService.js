import { api } from './api.js'

export async function getSuspiciousActivities(filters = {}) {
  const response = await api.get('/suspicious', {
    params: {
      username: filters.username || undefined,
      ip_address: filters.ipAddress || undefined,
      activityType: filters.activityType || undefined,
    },
  })
  return response.data
}
