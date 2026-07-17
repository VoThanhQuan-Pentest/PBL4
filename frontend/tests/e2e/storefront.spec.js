import { expect, test } from '@playwright/test';

async function login(page, username, password) {
  await page.locator('#account-icon').click();
  await page.locator('#username').fill(username);
  await page.locator('#password').fill(password);
  const loginResponse = page.waitForResponse(response =>
    response.url().endsWith('/api/auth/login') && response.request().method() === 'POST'
  );
  const productsReloaded = page.waitForResponse(response =>
    /\/api\/(?:admin\/)?products(?:[/?]|$)/.test(response.url())
      && response.request().method() === 'GET'
  );
  await page.locator('#login-form').press('Enter');
  expect((await loginResponse).ok()).toBe(true);
  expect((await productsReloaded).ok()).toBe(true);
  await expect(page.locator('#login-overlay')).toBeHidden();
  await expect(page.locator('#dropdown-user-name')).not.toHaveText('Khách');
}

test('guest can browse and search the catalog without console errors', async ({ page }) => {
  const errors = [];
  page.on('console', message => {
    if (message.type() === 'error') errors.push(message.text());
  });
  page.on('pageerror', error => errors.push(error.message));

  await page.goto('/');
  await expect(page.locator('.product-card').first()).toBeVisible();
  await page.locator('#search-input').fill('Nike');
  await expect(page.locator('.product-card').first()).toBeVisible();
  await expect(page.locator('img')).not.toHaveCount(0);
  expect(errors.filter(error => !error.includes('status of 401') && !error.includes('favicon'))).toEqual([]);
});

test('customer session uses the browser cookie and can add a product to cart', async ({ page }) => {
  await page.goto('/');
  await login(page, 'e2e_customer', 'CustomerE2E#1');
  await page.locator('a[data-collection="hot"]').click();
  const addToCartButton = page.locator('.add-to-cart-btn:visible').first();
  await expect(addToCartButton).toBeVisible({ timeout: 10_000 });
  await addToCartButton.click();
  await expect(page.locator('#cart-item-overlay')).toBeVisible();
  await page.locator('#cart-item-form button[type="submit"]').click();
  await expect(page.locator('#cart-count')).not.toHaveText('0');
  await page.locator('#cart-link').click();
  await expect(page.locator('#cart-view')).toBeVisible();
});

test('staff and admin see only their permitted workspace controls', async ({ page }) => {
  await page.goto('/');
  await login(page, 'e2e_staff', 'StaffE2E#1');
  await page.locator('#account-icon').click();
  await page.locator('#admin-link a').click();
  await expect(page.locator('#admin-panel')).toBeVisible();
  await expect(page.locator('#user-mgmt-panel')).toHaveCount(0);

  await page.context().clearCookies();
  await page.reload();
  await login(page, 'e2e_admin', 'AdminE2E#1');
  await page.locator('#account-icon').click();
  await page.locator('#admin-link a').click();
  await expect(page.locator('#admin-panel')).toBeVisible();
});
