import { API_BASE } from './config.js';

let tokenPromise;

export async function getCsrfToken() {
  if (!tokenPromise) {
    tokenPromise = fetch(`${API_BASE}/auth/csrf`, { credentials: 'same-origin' })
      .then(response => {
        if (!response.ok) {
          throw new Error('Unable to obtain CSRF token');
        }
        return response.json();
      })
      .then(payload => {
        const token = typeof payload?.token === 'string' ? payload.token.trim() : '';
        if (!token) {
          throw new Error('Unable to obtain CSRF token');
        }
        return token;
      });
  }

  const activeTokenPromise = tokenPromise;
  try {
    return await activeTokenPromise;
  } catch (error) {
    if (tokenPromise === activeTokenPromise) {
      tokenPromise = undefined;
    }
    throw error;
  }
}

export function resetCsrfToken() {
  tokenPromise = undefined;
}
