import { expect, test } from '@playwright/test';
const base = 'https://app.soc.test:8443';

async function csrf(client) {
  const response = await client.get('/api/auth/csrf');
  expect(response.status()).toBe(200);
  return (await response.json()).token;
}
const mailpit = 'http://127.0.0.1:8025';
async function login(client) {
  const before = new Set((await (await client.get(mailpit + '/api/v1/messages')).json()).messages.map(m => m.ID));
  // Repeated synthetic logins obey the production cooldown; never relax the limit for tests.
  let response;
  for (let attempt = 0; attempt < 2; attempt++) {
    response = await client.post('/api/auth/login', {
      data: { username: 'e2e_customer', password: 'CustomerE2E#1' },
      headers: { 'X-XSRF-TOKEN': await csrf(client) }
    });
    if (response.status() !== 429 || attempt === 1) break;
    await new Promise(resolve => setTimeout(resolve, 61000));
  }
  expect(response.status()).toBe(202);
  expect(response.headers()['set-cookie']?.includes('access_token=') ?? false).toBe(false);
  const challenge = await response.json();
  expect((await client.get('/api/auth/me')).status()).toBe(401);
  let code;
  await expect.poll(async () => {
    const messages = (await (await client.get(mailpit + '/api/v1/messages')).json()).messages;
    const message = messages.find(m => !before.has(m.ID) && m.Subject === 'Flare - OTP dang nhap'
      && m.To.some(to => to.Address === 'customer.e2e@flarefitness.test'));
    if (!message) return false;
    const detail = await (await client.get(mailpit + '/api/v1/message/' + message.ID)).json();
    code = detail.Text.match(/\b[0-9]{6}\b/)?.[0];
    return Boolean(code);
  }, { timeout: 15000 }).toBe(true);
  const verified = await client.post('/api/auth/login/otp', {
    data: { challenge_id: challenge.challenge_id, otp_code: code },
    headers: { 'X-XSRF-TOKEN': await csrf(client) }
  });
  expect(verified.status()).toBe(200);
  expect((await (await client.get('/api/auth/me')).json()).username).toBe('e2e_customer');
}

test('trusted HTTPS enforces secure cookies and blocks cross-site private-state mutation', async ({ page, context }) => {
  await page.goto('/');
  await login(page.request);
  const cookie = (await context.cookies(base)).find(c => c.name === 'access_token');
  // Never assert/print a complete cookie object or its secret value.
  expect(Boolean(cookie)).toBe(true);
  expect(cookie.secure).toBe(true);
  expect(cookie.httpOnly).toBe(true);
  expect(cookie.sameSite).toBe('Strict');
  expect((await page.request.get('http://app.soc.test:8088/api/auth/me')).status()).toBe(401);
  const before = await (await page.request.get('/api/sync/me/cart')).json();
  await page.goto('https://attacker.test:8443/');
  const result = await page.evaluate(async () => {
    try {
      await fetch('https://app.soc.test:8443/api/sync/me/cart', {
        method: 'PUT', credentials: 'include', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ payload: '["cross-site-write"]' })
      });
      return 'unexpected-access';
    } catch { return 'blocked'; }
  });
  expect(result).toBe('blocked');
  const after = await (await page.request.get(base + '/api/sync/me/cart')).json();
  expect(after).toEqual(before);
});

test('revoked sessions remain unusable even when the old cookie is restored', async ({ page, context }) => {
  await login(page.request);
  const original = (await context.cookies(base)).filter(c => c.name === 'access_token');
  const response = await page.request.post('/api/auth/logout', { headers: { 'X-XSRF-TOKEN': await csrf(page.request) } });
  expect(response.status()).toBe(204);
  expect((await page.request.get('/api/auth/me')).status()).toBe(401);
  await context.addCookies(original);
  expect((await page.request.get('/api/auth/me')).status()).toBe(401);
});

test('HTTPS hostname verification is enabled', async ({ request }) => {
  await expect(request.get('https://127.0.0.1:8443/')).rejects.toThrow(/certificate|cert_|hostname|subject/i);
});
