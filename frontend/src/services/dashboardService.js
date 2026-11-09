import { api } from './api.js'

export async function getDashboardStatistics() {
  const response = await api.get('/dashboard')
  return response.data
}
