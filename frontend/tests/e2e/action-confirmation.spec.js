import { readFileSync } from 'node:fs';
import { expect, test } from '@playwright/test';

const moduleSource = readFileSync(new URL('../../src/core/sensitive-action-confirmation.js', import.meta.url), 'utf8');
const fixture = `<!doctype html><html lang="vi"><meta charset="utf-8"><title>OTP component fixture</title>
<body><div id="overlay"><form id="form"><label>Email đích <input id="target" value="new@example.test"></label>
<button id="submit" type="submit">Lưu thay đổi</button></form></div><p id="status" role="status"></p>
<button id="close" type="button">Đóng</button><script type="module">
import { confirmSensitiveAction } from '/fixture-module.js';
window.calls = []; window.current = true; window.accepted = '222222'; window.expired = false;
window.required = true; window.contactAvailable = true;
const apiRequest = async (path, options = {}) => {
  window.calls.push({ path, body: options.body });
  if (path.endsWith('/policy')) return { required: window.required, contact_available: window.contactAvailable };
  if (path === '/profile/action-confirmations') return { id: 'fixture-operation', operation: 'EMAIL_CHANGE',
    confirmation_email_masked: 'o***@example.test', expires_at: new Date(Date.now() + (window.expired ? -1000 : 120000)).toISOString() };
  if (options.body.confirmation_code !== window.accepted) throw Object.assign(new Error('Mã xác nhận sai'), { code: 'ACTION_CONFIRMATION_CODE_INVALID' });
  return { id: 'fixture-operation', operation: 'EMAIL_CHANGE', state: 'COMMITTED', profile: { email: 'new@example.test' } };
};
document.querySelector('#form').addEventListener('submit', async event => {
  event.preventDefault();
  if (window.pending) return;
  window.pending = true;
  try {
    const result = await confirmSensitiveAction({ apiRequest, operation: 'EMAIL_CHANGE',
      payload: { email: document.querySelector('#target').value, otp_code: '111111' },
      form: document.querySelector('#form'), overlay: document.querySelector('#overlay'), isAuthCurrent: () => window.current });
    document.querySelector('#status').textContent = result ? result.state : 'LEGACY_ROUTE';
  } catch (error) { document.querySelector('#status').textContent = error.message; }
  finally { window.pending = false; }
});
document.querySelector('#close').addEventListener('click', () => {
  document.querySelector('#overlay').dispatchEvent(new Event('overlay:close'));
  document.querySelector('#overlay').hidden = true;
});
window.fixtureReady = true;
</script></body></html>`;

test.beforeEach(async ({ page }) => {
  await page.route('**/fixture-module.js', route => route.fulfill({ contentType: 'text/javascript', body: moduleSource }));
  await page.route('**/otp-component-fixture', route => route.fulfill({ contentType: 'text/html', body: fixture }));
  await page.goto('/otp-component-fixture');
  await page.waitForFunction(() => window.fixtureReady);
});

test('shows current-mailbox confirmation, freezes payload and supports keyboard execution once', async ({ page }) => {
  await page.locator('#submit').click();
  await expect(page.getByText(/Nhập mã gửi tới email hiện tại o\*\*\*@example.test/)).toBeVisible();
  await expect(page.locator('#target')).toBeDisabled();
  await page.getByRole('textbox', { name: 'Mã xác nhận thao tác 6 số' }).fill('222222');
  await page.getByRole('textbox', { name: 'Mã xác nhận thao tác 6 số' }).press('Enter');
  await expect(page.locator('#status')).toHaveText('COMMITTED');
  const executions = await page.evaluate(() => window.calls.filter(c => c.path.endsWith('/execute')));
  expect(executions).toHaveLength(1);
  expect(executions[0].body).toEqual({ confirmation_code: '222222', destination_otp_code: '111111',
    request_id: expect.stringMatching(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/) });
  await expect(page.locator('section')).toHaveCount(0);
});

test('code typo retries the same immutable operation without another preparation/send', async ({ page }) => {
  await page.locator('#submit').click();
  await page.getByRole('textbox', { name: 'Mã xác nhận thao tác 6 số' }).fill('000000');
  await page.getByRole('button', { name: 'Xác nhận thao tác', exact: true }).click();
  await expect(page.getByRole('alert')).toHaveText('Mã xác nhận sai');
  await page.getByRole('textbox', { name: 'Mã xác nhận thao tác 6 số' }).fill('222222');
  await page.getByRole('button', { name: 'Xác nhận thao tác', exact: true }).click();
  await expect(page.locator('#status')).toHaveText('COMMITTED');
  expect(await page.evaluate(() => window.calls.filter(c => c.path === '/profile/action-confirmations').length)).toBe(1);
});

test('cancelling or closing the overlay never executes and restores form controls', async ({ page }) => {
  await page.locator('#submit').click();
  await page.getByRole('button', { name: 'Hủy', exact: true }).click();
  await expect(page.locator('#status')).toContainText('Đã hủy');
  await expect(page.locator('#target')).toBeEnabled();
  await page.locator('#submit').click();
  await expect(page.locator('section')).toHaveCount(1);
  await page.locator('#close').click();
  await expect(page.locator('section')).toHaveCount(0);
  expect(await page.evaluate(() => window.calls.some(c => c.path.endsWith('/execute')))).toBe(false);
});

test('expired confirmation and account switch cannot execute', async ({ page }) => {
  await page.evaluate(() => { window.expired = true; });
  await page.locator('#submit').click();
  await expect(page.locator('#status')).toContainText('hết hạn');
  await expect(page.locator('#target')).toBeEnabled();
  await page.evaluate(() => { window.expired = false; });
  await page.locator('#submit').click();
  await page.getByRole('textbox', { name: 'Mã xác nhận thao tác 6 số' }).fill('222222');
  await page.evaluate(() => { window.current = false; });
  await page.getByRole('button', { name: 'Xác nhận thao tác', exact: true }).click();
  await expect(page.locator('#status')).toContainText('Phiên đăng nhập');
  expect(await page.evaluate(() => window.calls.some(c => c.path.endsWith('/execute')))).toBe(false);
});

test('unverified contact blocks preparation rather than accepting the destination email proof', async ({ page }) => {
  await page.evaluate(() => { window.contactAvailable = false; });
  await page.locator('#submit').click();
  await expect(page.locator('#status')).toContainText('chưa có bằng chứng');
  expect(await page.evaluate(() => window.calls.length)).toBe(1);
});
