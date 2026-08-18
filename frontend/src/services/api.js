import axios from 'axios';

const api = axios.create({
  // 127.0.0.1, not "localhost" -- resolving "localhost" costs ~2s on first
  // use on Windows (IPv6 attempted before falling back to IPv4).
  baseURL: 'http://127.0.0.1:3001',
  timeout: 10000,
});

// Attach JWT token from localStorage to every request
api.interceptors.request.use((config) => {
  const token = localStorage.getItem('dlp_token');
  if (token) config.headers.Authorization = `Bearer ${token}`;
  return config;
});

// Redirect to login on 401
api.interceptors.response.use(
  (res) => res,
  (err) => {
    if (err.response?.status === 401) {
      localStorage.removeItem('dlp_token');
      localStorage.removeItem('dlp_user');
      window.location.href = '/login';
    }
    return Promise.reject(err);
  }
);

export default api;
