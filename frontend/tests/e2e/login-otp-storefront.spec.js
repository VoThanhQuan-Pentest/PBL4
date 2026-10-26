import { readFileSync, existsSync, statSync } from 'node:fs';
import { resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { expect, test } from '@playwright/test';

const dist = fileURLToPath(new URL('../../dist/', import.meta.url));
const user = { id: 'otp-login-ui', username: 'synthetic-login', role: 'CUSTOMER', ho_ten: 'OTP login fixture', email: 'owner@example.test' };

async function storefront(page) {
  let authenticated = false;
  let passwordSubmissions = 0;
  let otpSubmissions = 0;
  await page.route('**/*', async route => {
    const req = route.request();
    const url = new URL(req.url());
    if (url.origin !== 'http://127.0.0.1:8088') return route.abort();
    const path = url.pathname;
    const respond = (body, status = 200) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });
    if (path.startsWith('/api/')) {
      if (path === '/api/auth/csrf') return respond({ token: 'synthetic-csrf' });
      if (path === '/api/auth/me') return authenticated ? respond(user) : respond({ message: 'Unauthenticated' }, 401);
      if (path === '/api/auth/login') {
        passwordSubmissions++;
        return respond({ challenge_id: '12345678-1234-1234-1234-123456789012', expires_in: 300, email_masked: 'o***@example.test', channel: 'EMAIL_OTP' }, 202);
      }
      if (path === '/api/auth/login/otp') {
        otpSubmissions++;
        const body = req.postDataJSON();
        if (body.challenge_id !== '12345678-1234-1234-1234-123456789012' || body.otp_code !== '123456') return respond({ message: 'OTP không hợp lệ' }, 401);
        authenticated = true;
        return respond({ access_token: null, expires_in: 3600, user });
      }
      if (path === '/api/profile') return respond(user);
      if (path.startsWith('/api/products/')) return respond({ content: [], has_next: false });
      if (path.startsWith('/api/sync/app/')) return respond({ value: null });
      if (path.startsWith('/api/sync/')) return respond({ value: [] });
      return respond([]);
    }
    const relative = decodeURIComponent(path === '/' ? '/index.html' : path);
    const file = resolve(dist, '.' + relative);
    if (!file.startsWith(resolve(dist) + sep) || !existsSync(file) || !statSync(file).isFile()) return route.fulfill({ status: 404, body: '' });
    return route.fulfill({ contentType: file.endsWith('.js') ? 'text/javascript' : file.endsWith('.css') ? 'text/css' : file.endsWith('.html') ? 'text/html' : 'application/octet-stream', body: readFileSync(file) });
  });
  await page.goto('http://127.0.0.1:8088/');
  await page.locator('#account-icon').focus();
  await page.keyboard.press('Enter');
  await expect(page.locator('#login-overlay')).toBeVisible();
  return { passwordSubmissions: () => passwordSubmissions, otpSubmissions: () => otpSubmissions };
}

test('password step shows OTP without authenticating; only a valid code opens the account', async ({ page }) => {
  const app = await storefront(page);
  await page.locator('#username').fill(user.username);
  await page.locator('#password').fill('Synthetic!Password1');
  await page.locator('#login-form').evaluate(form => { form.requestSubmit(); form.requestSubmit(); });
  await expect(page.locator('#login-otp-group')).toBeVisible();
  await expect(page.locator('#password')).toHaveValue('');
  await expect(page.locator('#username')).toBeDisabled();
  expect(app.passwordSubmissions()).toBe(1);
  await expect(page.locator('#login-overlay')).toBeVisible();
  await page.locator('#login-otp-code').fill('000000');
  await page.locator('#login-form button[type="submit"]').click();
  await expect(page.locator('#login-error')).toContainText('OTP');
  await expect(page.locator('#login-otp-code')).toHaveValue('');
  await page.locator('#login-otp-code').fill('123456');
  await page.locator('#login-form button[type="submit"]').click();
  await expect(page.locator('#login-overlay')).toBeHidden();
  await expect(page.locator('#dropdown-user-name')).toHaveText(user.ho_ten);
  expect(app.otpSubmissions()).toBe(2);
  const browserStorage = await page.evaluate(() => JSON.stringify({ local: { ...localStorage }, session: { ...sessionStorage } }));
  expect(browserStorage).not.toContain('Synthetic!Password1');
  expect(browserStorage).not.toContain('12345678-1234-1234-1234-123456789012');
});

test('closing a pending login discards OTP and restores the password form', async ({ page }) => {
  await storefront(page);
  await page.locator('#username').fill(user.username);
  await page.locator('#password').fill('Synthetic!Password1');
  await page.locator('#login-form button[type="submit"]').click();
  await expect(page.locator('#login-otp-group')).toBeVisible();
  await page.locator('#login-otp-code').fill('123456');
  await page.locator('#close-login').click();
  await page.locator('#account-icon').focus(); await page.keyboard.press('Enter');
  await expect(page.locator('#login-otp-group')).toBeHidden();
  await expect(page.locator('#login-otp-code')).toHaveValue('');
  await expect(page.locator('#password')).toBeEnabled();
  await expect(page.locator('#password')).toHaveValue('');
});
