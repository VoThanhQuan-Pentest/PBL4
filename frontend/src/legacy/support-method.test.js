import { readFileSync } from 'node:fs';
import { describe, expect, it, vi } from 'vitest';

const source = readFileSync(new URL('./main.js', import.meta.url), 'utf8');
const start = source.indexOf('    async function syncCustomerSupportThreadFromApi(');
const end = source.indexOf('    async function syncWorkspaceSupportThreadsFromApi(', start);
if (start < 0 || end < start) throw new Error('Support sync function boundaries missing');

function fixture(apiRequest, current = true) {
  return new Function('apiRequest', 'current', `
    const currentUser = { id: 'owned-customer' };
    const canAccessWorkspace = () => false;
    const captureAuthContext = () => ({ workspaceAccess: false });
    const isAuthContextCurrent = () => current;
    const upsertSupportThread = value => value;
    const getCustomerSupportThread = () => null;
    const isStaleAuthContextError = () => true;
    ${source.slice(start, end)}
    return syncCustomerSupportThreadFromApi;
  `)(apiRequest, current);
}

describe('customer support HTTP methods', () => {
  it('uses POST through the shared authenticated CSRF helper to initialize a welcome thread', async () => {
    const api = vi.fn().mockResolvedValue({ id: 'owned-thread' });
    expect(await fixture(api)(true)).toEqual({ id: 'owned-thread' });
    expect(api).toHaveBeenCalledExactlyOnceWith('/support/me', { method: 'POST' });
  });

  it('keeps polling read-only and handles a missing thread', async () => {
    const api = vi.fn().mockResolvedValue(null);
    expect(await fixture(api)(false)).toBeNull();
    expect(api).toHaveBeenCalledExactlyOnceWith('/support/me', { method: 'GET' });
  });

  it('does not restore a completed initialization from an obsolete authentication context', async () => {
    const api = vi.fn().mockResolvedValue({ id: 'obsolete-thread' });
    expect(await fixture(api, false)(true)).toBeNull();
  });
});
