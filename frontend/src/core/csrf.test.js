import { afterEach, describe, expect, it, vi } from 'vitest';

afterEach(() => {
  vi.restoreAllMocks();
  vi.resetModules();
});

describe('getCsrfToken', () => {
  it('uses same-origin credentials and shares one in-flight request', async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ token: 'csrf-token' })
    });
    const { getCsrfToken } = await import('./csrf.js');

    await expect(Promise.all([getCsrfToken(), getCsrfToken()])).resolves.toEqual(['csrf-token', 'csrf-token']);
    expect(globalThis.fetch).toHaveBeenCalledTimes(1);
    expect(globalThis.fetch).toHaveBeenCalledWith('/api/auth/csrf', { credentials: 'same-origin' });
  });

  it('allows a retry after a failed token request', async () => {
    globalThis.fetch = vi.fn()
      .mockResolvedValueOnce({ ok: false, json: async () => ({}) })
      .mockResolvedValueOnce({ ok: true, json: async () => ({ token: 'replacement' }) });
    const { getCsrfToken } = await import('./csrf.js');

    await expect(getCsrfToken()).rejects.toThrow('Unable to obtain CSRF token');
    await expect(getCsrfToken()).resolves.toBe('replacement');
  });

  it('does not cache a successful response with a missing token', async () => {
    globalThis.fetch = vi.fn()
      .mockResolvedValueOnce({ ok: true, json: async () => ({ token: '   ' }) })
      .mockResolvedValueOnce({ ok: true, json: async () => ({ token: 'replacement' }) });
    const { getCsrfToken } = await import('./csrf.js');

    await expect(getCsrfToken()).rejects.toThrow('Unable to obtain CSRF token');
    await expect(getCsrfToken()).resolves.toBe('replacement');

    expect(globalThis.fetch).toHaveBeenCalledTimes(2);
  });

  it('fetches a fresh token after the authentication state changes', async () => {
    globalThis.fetch = vi.fn()
      .mockResolvedValueOnce({ ok: true, json: async () => ({ token: 'guest-token' }) })
      .mockResolvedValueOnce({ ok: true, json: async () => ({ token: 'authenticated-token' }) });
    const { getCsrfToken, resetCsrfToken } = await import('./csrf.js');

    await expect(getCsrfToken()).resolves.toBe('guest-token');
    resetCsrfToken();
    await expect(getCsrfToken()).resolves.toBe('authenticated-token');

    expect(globalThis.fetch).toHaveBeenCalledTimes(2);
  });
});
