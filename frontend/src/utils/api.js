import axios from 'axios';

const API_BASE = process.env.REACT_APP_API_URL || '/api/v1';

const api = axios.create({
  baseURL: API_BASE,
  headers: {
    'Content-Type': 'application/json',
  },
  withCredentials: true,
  timeout: 60000,
});

// Request interceptor
api.interceptors.request.use(config => {
  return config;
}, error => Promise.reject(error));

// Response interceptor
api.interceptors.response.use(
  response => response.data,
  error => {
    const message = error.response?.data?.detail || error.message || 'Request failed';
    return Promise.reject(new Error(message));
  }
);

export const emailAPI = {
  analyzeEmail: (data) => api.post('/analyze', data),
  getAnalysis: (id) => api.get(`/analyses/${id}`),
  listAnalyses: (params) => api.get('/analyses', { params }),
  submitFeedback: (id, feedback) => api.post(`/analyses/${id}/feedback`, feedback),
  getDashboardStats: (days = 30) => api.get('/dashboard/stats', { params: { days } }),
  getHealth: () => api.get('/health'),
};

export const authAPI = {
  login: (payload) => api.post('/auth/login', payload),
  logout: () => api.post('/auth/logout'),
  me: () => api.get('/auth/me'),
};

export default api;
