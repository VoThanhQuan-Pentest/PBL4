import { readFileSync, existsSync, statSync } from 'node:fs';
import { resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { expect, test } from '@playwright/test';

// Serve the actual production HTML/JS/CSS. Only API responses are controlled;
// no fixture implementation or test-only submit handler replaces the storefront.
const dist = fileURLToPath(new URL('../../dist/', import.meta.url));
const apiBase = '/api/profile/action-confirmations';
const initialUser = { id: 'otp-ui-lab', username: 'otp-ui-lab', role: 'CUSTOMER',
  ho_ten: 'Lab owner', email: 'owner@example.test', sdt: '' };

async function storefront(page, { gatePreparation = false, policyRequired = true, policyFailure = false,
  rejectFirstCode = false } = {}) {
  const requests = [];
  let release;
  const gate = new Promise(resolve => { release = resolve; });
  let prepared;
  let user = { ...initialUser };
  let executions = 0;
  page.on('dialog', dialog => dialog.accept());
  await page.route('**/*', async route => {
    const request = route.request();
    const url = new URL(request.url());
    if (url.origin !== 'http://127.0.0.1:8088') return route.abort();
    const path = url.pathname;
    if (path.startsWith('/api/')) {
      const body = request.postData() ? request.postDataJSON() : null;
      requests.push({ path, method: request.method(), body });
      const respond = (value, status = 200) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(value) });
      if (path === '/api/auth/csrf') return respond({ token: 'controlled-csrf' });
      if (path === '/api/auth/me' || path === '/api/profile' && request.method() === 'GET') return respond(user);
      if (path === apiBase + '/policy') return policyFailure
        ? respond({ code: 'SERVICE_UNAVAILABLE', message: 'Policy unavailable' }, 503)
        : respond({ required: policyRequired, contact_available: true });
      if (path === apiBase) {
        prepared = body;
        if (gatePreparation) await gate;
        return respond({ id: 'immutable-action', operation: body.operation,
          expires_at: new Date(Date.now() + 120000).toISOString(), confirmation_email_masked: 'o***@example.test' });
      }
      if (path === apiBase + '/immutable-action/execute') {
        executions += 1;
        if (rejectFirstCode && executions === 1) return respond({
          code: 'ACTION_CONFIRMATION_CODE_INVALID', message: 'Mã xác nhận sai' }, 400);
        if (prepared.operation === 'EMAIL_CHANGE') user = { ...user, email: prepared.profile.email, ho_ten: prepared.profile.ho_ten };
        return respond({ id: 'immutable-action', operation: prepared.operation, state: 'COMMITTED', profile: user });
      }
      if (path === '/api/profile' && request.method() === 'PUT') {
        user = { ...user, ho_ten: body.ho_ten, email: body.email, sdt: body.sdt }; return respond(user);
      }
      if (path === '/api/profile/password') return route.fulfill({ status: 204, body: '' });
      if (path.startsWith('/api/products/')) return respond({ content: [], has_next: false });
      if (path.startsWith('/api/sync/app/')) return respond({ value: null });
      if (path.startsWith('/api/sync/')) return respond({ value: [] });
      return respond([]);
    }
    const relative = decodeURIComponent(path === '/' ? '/index.html' : path).slice(1);
    const file = resolve(dist, relative);
    if (!file.startsWith(resolve(dist) + sep) || !existsSync(file) || !statSync(file).isFile()) return route.fulfill({ status: 404, body: '' });
    const type = file.endsWith('.js') ? 'text/javascript' : file.endsWith('.css') ? 'text/css'
      : file.endsWith('.html') ? 'text/html' : 'application/octet-stream';
    return route.fulfill({ contentType: type, body: readFileSync(file) });
  });
  await page.goto('http://127.0.0.1:8088/');
  await expect(page.locator('#dropdown-user-name')).toHaveText(initialUser.ho_ten);
  return { requests, release, preparations: () => requests.filter(r => r.path === apiBase),
    executions: () => requests.filter(r => r.path.endsWith('/execute')) };
}

async function openForm(page, operation) {
  // CDN icon fonts are blocked in this offline test; use native keyboard navigation.
  await page.locator('#account-icon').focus();
  await page.keyboard.press('Enter');
  if (operation === 'EMAIL_CHANGE') {
    await page.locator('#edit-profile-link').click();
    await expect(page.locator('#profile-overlay')).toBeVisible();
    await page.locator('#edit-email').fill('destination@example.test');
    await page.locator('#edit-email-otp').fill('111111');
    return '#profile-form';
  }
  await page.locator('#change-pass-link').click();
  await expect(page.locator('#password-overlay')).toBeVisible();
  await page.locator('#current-password').fill('CurrentPassword1!');
  await page.locator('#new-password').fill('ReplacementPassword2!');
  await page.locator('#confirm-password').fill('ReplacementPassword2!');
  return '#password-form';
}

for (const operation of ['EMAIL_CHANGE', 'PASSWORD_CHANGE']) {
  test(`${operation}: duplicate real-form submit prepares and executes once`, async ({ page }) => {
    const app = await storefront(page, { gatePreparation: true });
    const form = await openForm(page, operation);
    await page.locator(form).evaluate(element => { element.requestSubmit(); element.requestSubmit(); });
    await expect.poll(() => app.preparations().length).toBeGreaterThan(0);
    app.release();
    await expect(page.getByRole('textbox', { name: 'Mã xác nhận thao tác 6 số' })).toHaveCount(1);
    await page.getByRole('textbox', { name: 'Mã xác nhận thao tác 6 số' }).fill('222222');
    await page.getByRole('button', { name: 'Xác nhận thao tác', exact: true }).click();
    await expect(page.locator(operation === 'EMAIL_CHANGE' ? '#profile-overlay' : '#password-overlay')).toBeHidden();
    expect(app.preparations()).toHaveLength(1);
    expect(app.executions()).toHaveLength(1);
    expect(app.requests.filter(r => r.method === 'PUT')).toHaveLength(0);
    expect(app.preparations()[0].body.operation).toBe(operation);
    expect(app.executions()[0].body).toEqual({ confirmation_code: '222222', destination_otp_code: operation === 'EMAIL_CHANGE' ? '111111' : '',
      request_id: expect.stringMatching(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/) });
    if (operation === 'PASSWORD_CHANGE') {
      await expect(page.locator('#login-overlay')).toBeVisible();
      await expect(page.locator('#current-password')).toHaveValue('');
    }
  });
}

test('real email form propagates invalid-code errors and retries the same action', async ({ page }) => {
  const app = await storefront(page, { rejectFirstCode: true });
  const form = await openForm(page, 'EMAIL_CHANGE');
  await page.locator(form).locator('button[type="submit"]').click();
  const code = page.getByRole('textbox', { name: 'Mã xác nhận thao tác 6 số' });
  await code.fill('000000');
  await page.getByRole('button', { name: 'Xác nhận thao tác', exact: true }).click();
  await expect(page.getByRole('alert')).toHaveText('Mã xác nhận sai');
  await code.fill('222222');
  await page.getByRole('button', { name: 'Xác nhận thao tác', exact: true }).click();
  await expect(page.locator('#profile-overlay')).toBeHidden();
  expect(app.preparations()).toHaveLength(1);
  expect(app.executions()).toHaveLength(2);
  expect(app.requests.filter(r => r.method === 'PUT')).toHaveLength(0);
});

test('closing the real form during preparation cancels the pending UI flow', async ({ page }) => {
  const app = await storefront(page, { gatePreparation: true });
  const form = await openForm(page, 'EMAIL_CHANGE');
  await page.locator(form).locator('button[type="submit"]').click();
  await expect.poll(() => app.preparations().length).toBe(1);
  await page.locator('#close-profile').click();
  app.release();
  await expect(page.locator('#profile-error')).toContainText('Đã hủy');
  await expect(page.getByRole('textbox', { name: 'Mã xác nhận thao tác 6 số' })).toHaveCount(0);
  await expect(page.locator('#edit-email')).toBeEnabled();
  expect(app.executions()).toHaveLength(0);
});

test('a policy failure in the real password form never falls back to the legacy mutation', async ({ page }) => {
  const app = await storefront(page, { policyFailure: true });
  const form = await openForm(page, 'PASSWORD_CHANGE');
  await page.locator(form).locator('button[type="submit"]').click();
  await expect(page.locator('#pass-error')).toHaveText('Policy unavailable');
  expect(app.preparations()).toHaveLength(0);
  expect(app.requests.filter(r => r.method === 'PUT')).toHaveLength(0);
});

test('the real password form preserves the server-disabled policy path', async ({ page }) => {
  const app = await storefront(page, { policyRequired: false });
  const form = await openForm(page, 'PASSWORD_CHANGE');
  await page.locator(form).locator('button[type="submit"]').click();
  await expect(page.locator('#login-overlay')).toBeVisible();
  expect(app.preparations()).toHaveLength(0);
  expect(app.requests.filter(r => r.method === 'PUT')).toEqual([{ path: '/api/profile/password', method: 'PUT',
    body: { current_password: 'CurrentPassword1!', new_password: 'ReplacementPassword2!', confirm_password: 'ReplacementPassword2!' } }]);
});


test('direct recovery-email change requires a transient password when the optional policy is off', async ({ page }) => {
  const app = await storefront(page, { policyRequired: false });
  const form = await openForm(page, 'EMAIL_CHANGE');
  await page.locator(form).locator('button[type="submit"]').click();
  await expect(page.locator('#profile-error')).toContainText('mật khẩu hiện tại');
  expect(app.requests.filter(r => r.path === '/api/profile' && r.method === 'PUT')).toHaveLength(0);
  await page.locator('#edit-email-password').fill('CurrentPassword1!');
  await page.locator(form).locator('button[type="submit"]').click();
  await expect(page.locator('#profile-overlay')).toBeHidden();
  const writes = app.requests.filter(r => r.path === '/api/profile' && r.method === 'PUT');
  expect(writes).toHaveLength(1);
  expect(writes[0].body.current_password).toBe('CurrentPassword1!');
  expect(writes[0].body.otp_code).toBe('111111');
  await expect(page.locator('#edit-email-password')).toHaveValue('');
  const storage = await page.evaluate(() => JSON.stringify([Object.entries(localStorage), Object.entries(sessionStorage)]));
  expect(storage).not.toContain('CurrentPassword1!');
});

test('closing the real profile form clears its recovery-email password', async ({ page }) => {
  await storefront(page, { policyRequired: false });
  await openForm(page, 'EMAIL_CHANGE');
  await page.locator('#edit-email-password').fill('CurrentPassword1!');
  await page.locator('#close-profile').click();
  await expect(page.locator('#profile-overlay')).toBeHidden();
  await expect(page.locator('#edit-email-password')).toHaveValue('');
});
