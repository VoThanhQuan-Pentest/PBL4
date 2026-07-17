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
      .then(payload => payload.token);
  }

  try {
    return await tokenPromise;
  } catch (error) {
    tokenPromise = undefined;
    throw error;
  }
}

export function resetCsrfToken() {
  tokenPromise = undefined;
}
