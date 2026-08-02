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

test('public reviews render without requesting or caching legacy metadata', async ({ page }) => {
  const legacySyncRequests = [];
  page.on('request', request => {
    if (request.url().includes('/api/sync/app/managed-reviews')) {
      legacySyncRequests.push(request.url());
    }
  });
  await page.route('**/api/reviews/products/*/page**', route => {
    const productId = new URL(route.request().url()).pathname.split('/').at(-2);
    return route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        content: [{
          id: 'public-review-e2e',
          productId,
          reviewer: 'Khách kiểm thử',
          rating: 5,
          content: 'Đánh giá công khai an toàn',
          createdAt: '2026-07-29T12:00:00',
          orderId: 'other-customers-order',
          userId: 'other-customer',
          status: 'Ẩn'
        }],
        page: 0,
        size: 20,
        totalElements: 1,
        totalPages: 1,
        hasNext: false
      })
    });
  });

  await page.goto('/');
  await page.locator('.product-card').first().click();
  await expect(page.locator('.product-reviewer')).toHaveText('Khách kiểm thử');

  const cachedReviews = await page.evaluate(() =>
    JSON.parse(sessionStorage.getItem('pbl3_managed_reviews') || '[]')
  );
  expect(cachedReviews).toEqual([
    expect.objectContaining({
      id: 'public-review-e2e',
      status: 'Hiển thị'
    })
  ]);
  expect(cachedReviews[0]).not.toHaveProperty('orderId');
  expect(cachedReviews[0]).not.toHaveProperty('userId');
  expect(legacySyncRequests).toEqual([]);
});

test('catalog API failure shows an error instead of manufactured products', async ({ page }) => {
  let allowCatalogRecovery = false;
  await page.route('**/api/products/query**', route => {
    if (allowCatalogRecovery) {
      return route.continue();
    }
    return route.fulfill({
      status: 503,
      contentType: 'application/json',
      body: JSON.stringify({ message: 'Catalog unavailable' })
    });
  });

  await page.goto('/');

  await expect(page.locator('#product-container .error-text')).toContainText('Không thể tải danh mục sản phẩm');
  await expect(page.locator('.product-card')).toHaveCount(0);

  allowCatalogRecovery = true;
  await page.locator('[data-retry-products]').click();
  await expect(page.locator('.product-card').first()).toBeVisible();
});

test('public catalog 401 stops at the error state without a request loop', async ({ page }) => {
  let catalogRequestCount = 0;
  await page.route('**/api/products/query**', route => {
    catalogRequestCount += 1;
    return route.fulfill({
      status: 401,
      contentType: 'application/json',
      body: JSON.stringify({ message: 'Public catalog authentication misconfigured' })
    });
  });

  await page.goto('/');
  await expect(page.locator('#product-container .error-text')).toContainText('Không thể tải danh mục sản phẩm');
  await page.waitForTimeout(750);
  expect(catalogRequestCount).toBeGreaterThan(0);
  expect(catalogRequestCount).toBeLessThanOrEqual(2);
});

test('a delayed bootstrap 401 cannot clear a newer login', async ({ page }) => {
  let releaseBootstrap;
  let markBootstrapSeen;
  const bootstrapGate = new Promise(resolve => {
    releaseBootstrap = resolve;
  });
  const bootstrapSeen = new Promise(resolve => {
    markBootstrapSeen = resolve;
  });
  let interceptBootstrap = true;

  await page.route('**/api/auth/me', async route => {
    if (!interceptBootstrap) {
      return route.continue();
    }
    interceptBootstrap = false;
    markBootstrapSeen();
    await bootstrapGate;
    return route.fulfill({
      status: 401,
      contentType: 'application/json',
      body: JSON.stringify({ message: 'Expired bootstrap session' })
    });
  });

  await page.goto('/');
  await bootstrapSeen;
  await login(page, 'e2e_customer', 'CustomerE2E#1');
  releaseBootstrap();

  await page.waitForTimeout(500);
  await expect(page.locator('#dropdown-user-name')).not.toHaveText('Khách');
  expect((await page.request.get('/api/auth/me')).status()).toBe(200);
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

test('logout revokes the browser session and restores guest UI', async ({ page }) => {
  await page.goto('/');
  await login(page, 'e2e_customer', 'CustomerE2E#1');

  await page.locator('#account-icon').click();
  const logoutResponse = page.waitForResponse(response =>
    response.url().endsWith('/api/auth/logout') && response.request().method() === 'POST'
  );
  await page.locator('#logout-link').click();

  expect((await logoutResponse).status()).toBe(204);
  await expect(page.locator('#dropdown-user-name')).toHaveText('Khách');
  expect((await page.request.get('/api/auth/me')).status()).toBe(401);
});

test('auth mutations serialize a delayed logout before a newer cross-tab login', async ({ page, context }) => {
  await page.goto('/');
  await login(page, 'e2e_customer', 'CustomerE2E#1');

  const secondPage = await context.newPage();
  await secondPage.goto('/');
  await expect(secondPage.locator('#dropdown-user-name')).not.toHaveText('Khách');

  let releaseOldLogout;
  let markOldLogoutSeen;
  const oldLogoutGate = new Promise(resolve => {
    releaseOldLogout = resolve;
  });
  const oldLogoutSeen = new Promise(resolve => {
    markOldLogoutSeen = resolve;
  });
  await page.route('**/api/auth/logout', async route => {
    const backendResponse = await route.fetch();
    expect(backendResponse.status()).toBe(204);
    expect(backendResponse.headers()['set-cookie'] || '').not.toContain('access_token=');
    markOldLogoutSeen();
    await oldLogoutGate;
    return route.fulfill({ response: backendResponse });
  });

  await page.locator('#account-icon').click();
  await page.locator('#logout-link').click();
  await oldLogoutSeen;

  // The server has revoked the old customer token, while its real response
  // is still held by the route. Reloading now exposes an honest guest login
  // surface without manufacturing a response or mutating browser state.
  await secondPage.reload();
  await expect(secondPage.locator('#dropdown-user-name')).toHaveText('Khách');
  await secondPage.locator('#account-icon').click();
  await secondPage.locator('#username').fill('e2e_admin');
  await secondPage.locator('#password').fill('AdminE2E#1');

  let newerLoginSent = false;
  secondPage.on('request', request => {
    if (request.url().endsWith('/api/auth/login') && request.method() === 'POST') {
      newerLoginSent = true;
    }
  });
  const newerLoginResponse = secondPage.waitForResponse(response =>
    response.url().endsWith('/api/auth/login') && response.request().method() === 'POST'
  );
  const productsReloaded = secondPage.waitForResponse(response =>
    /\/api\/(?:admin\/)?products(?:[/?]|$)/.test(response.url())
      && response.request().method() === 'GET'
  );
  await secondPage.locator('#login-form').press('Enter');

  // The newer login must remain queued until the older cookie mutation has
  // completed and released the same-origin Web Lock.
  await secondPage.waitForTimeout(300);
  expect(newerLoginSent).toBe(false);

  releaseOldLogout();
  expect((await newerLoginResponse).ok()).toBe(true);
  expect((await productsReloaded).ok()).toBe(true);
  await expect(secondPage.locator('#dropdown-user-name')).not.toHaveText('Khách');
  await expect(secondPage.locator('#dropdown-user-role')).toContainText('Quản trị');
  await expect(page.locator('#dropdown-user-role')).toContainText('Quản trị');
  expect((await page.request.get('/api/auth/me')).status()).toBe(200);
});

test('a delayed real logout response cannot erase a newer auth cookie', async ({ page, context }) => {
  await page.goto('/');
  await login(page, 'e2e_customer', 'CustomerE2E#1');

  const secondPage = await context.newPage();
  let releaseOldLogout;
  let markOldLogoutFetched;
  const oldLogoutGate = new Promise(resolve => {
    releaseOldLogout = resolve;
  });
  const oldLogoutFetched = new Promise(resolve => {
    markOldLogoutFetched = resolve;
  });

  await page.route('**/api/auth/logout', async route => {
    const backendResponse = await route.fetch();
    expect(backendResponse.status()).toBe(204);
    expect(backendResponse.headers()['set-cookie'] || '').not.toContain('access_token=');
    markOldLogoutFetched();
    await oldLogoutGate;
    return route.fulfill({ response: backendResponse });
  });

  const delayedLogoutResponse = page.waitForResponse(response =>
    response.url().endsWith('/api/auth/logout') && response.request().method() === 'POST'
  );
  await page.locator('#account-icon').click();
  await page.locator('#logout-link').click();
  await oldLogoutFetched;

  await secondPage.goto('/');
  await expect(secondPage.locator('#dropdown-user-name')).toHaveText('Khách');

  // Deliberately bypass the application lock to prove the server protocol is
  // independently safe even for another same-origin client implementation.
  const directLoginStatus = await secondPage.evaluate(async credentials => {
    const csrfResponse = await fetch('/api/auth/csrf', { credentials: 'same-origin' });
    const csrf = await csrfResponse.json();
    const response = await fetch('/api/auth/login', {
      method: 'POST',
      credentials: 'same-origin',
      headers: {
        'Content-Type': 'application/json',
        'X-XSRF-TOKEN': csrf.token
      },
      body: JSON.stringify(credentials)
    });
    return response.status;
  }, { username: 'e2e_admin', password: 'AdminE2E#1' });
  expect(directLoginStatus).toBe(200);

  let meResponse = await context.request.get('/api/auth/me');
  expect(meResponse.status()).toBe(200);
  expect((await meResponse.json()).role).toBe('admin');

  // Deliver the older, genuine 204 after the newer login cookie exists.
  releaseOldLogout();
  expect((await delayedLogoutResponse).status()).toBe(204);

  await expect.poll(async () => (await context.request.get('/api/auth/me')).status()).toBe(200);
  meResponse = await context.request.get('/api/auth/me');
  expect((await meResponse.json()).role).toBe('admin');
});

test('failed logout keeps the authenticated session visible', async ({ page }) => {
  await page.goto('/');
  await login(page, 'e2e_customer', 'CustomerE2E#1');
  const authenticatedName = await page.locator('#dropdown-user-name').textContent();
  await page.route('**/api/auth/logout', route => route.fulfill({
    status: 403,
    contentType: 'application/json',
    body: JSON.stringify({ message: 'CSRF token rejected' })
  }));

  await page.locator('#account-icon').click();
  const logoutResponse = page.waitForResponse(response =>
    response.url().endsWith('/api/auth/logout') && response.request().method() === 'POST'
  );
  await page.locator('#logout-link').click();

  expect((await logoutResponse).status()).toBe(403);
  await expect(page.locator('#centered-message')).toBeVisible();
  await expect(page.locator('#dropdown-user-name')).toHaveText(authenticatedName || 'e2e_customer');
  expect((await page.request.get('/api/auth/me')).status()).toBe(200);
});

test('admin logout purges privileged product data before loading the public catalog', async ({ page }) => {
  await page.goto('/');
  await login(page, 'e2e_admin', 'AdminE2E#1');
  await page.locator('a[data-collection="hot"]').click();

  const managedProduct = page.locator('.product-card:visible').filter({ hasText: 'Nike E2E' }).first();
  await expect(managedProduct).toBeVisible();
  await managedProduct.click();
  await expect(page.locator('#product-detail-description')).toContainText('Disposable E2E fixture');
  await expect(page.locator('#product-detail-stock')).toContainText('Còn 20 sản phẩm');
  await page.evaluate(() => {
    document.querySelector('#cart-recommendations-grid').innerHTML = '<article>private-recommendation-marker</article>';
    document.querySelector('#cart-recommendations-section').classList.remove('hidden');
    document.querySelector('#voucher-applied-note').textContent = 'private-voucher-marker';
    document.querySelector('#checkout-voucher-applied-note').textContent = 'private-checkout-voucher-marker';
  });

  await page.locator('#account-icon').click();
  const logoutResponse = page.waitForResponse(response =>
    response.url().endsWith('/api/auth/logout') && response.request().method() === 'POST'
  );
  const publicCatalogResponse = page.waitForResponse(response =>
    response.url().includes('/api/products/query') && response.request().method() === 'GET'
  );
  await page.locator('#logout-link').click();

  expect((await logoutResponse).status()).toBe(204);
  expect((await publicCatalogResponse).ok()).toBe(true);
  await expect(page.locator('#dropdown-user-name')).toHaveText('Khách');
  await expect(page.locator('body')).not.toContainText('Disposable E2E fixture');
  await expect(page.locator('body')).not.toContainText('private-recommendation-marker');
  await expect(page.locator('body')).not.toContainText('private-voucher-marker');
  await expect(page.locator('#cart-recommendations-grid')).toBeEmpty();
  await expect(page.locator('#cart-recommendations-section')).toBeHidden();

  const publicProduct = page.locator('.product-card:visible').filter({ hasText: 'Nike E2E' }).first();
  await expect(publicProduct).toBeVisible();
  await publicProduct.click();
  await expect(page.locator('#product-detail-description')).not.toContainText('Disposable E2E fixture');
  await expect(page.locator('#product-detail-stock')).toContainText('Còn 10 sản phẩm');
});

test('a delayed admin support response cannot repopulate private state after logout', async ({ page }) => {
  await page.goto('/');
  await login(page, 'e2e_admin', 'AdminE2E#1');

  let releaseSupport;
  let markSupportRequested;
  const supportGate = new Promise(resolve => {
    releaseSupport = resolve;
  });
  const supportRequested = new Promise(resolve => {
    markSupportRequested = resolve;
  });
  await page.route('**/api/support/threads', async route => {
    markSupportRequested();
    await supportGate;
    return route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify([{
        id: 'support-secret-thread',
        accountKey: 'support-secret-account',
        customer: { email: 'support-secret@example.invalid', phone: '0900000000' },
        status: 'OPEN',
        messages: [{ id: 'message-secret', sender: 'customer', text: 'support-secret-message' }]
      }])
    });
  });

  await page.locator('#account-icon').click();
  await page.locator('#admin-link a').click();
  await supportRequested;

  await page.locator('#account-icon').click();
  await expect(page.locator('#logout-link')).toBeVisible();
  const logoutResponse = page.waitForResponse(response =>
    response.url().endsWith('/api/auth/logout') && response.request().method() === 'POST'
  );
  await page.locator('#logout-link').click({ force: true });
  expect((await logoutResponse).status()).toBe(204);
  releaseSupport();

  await page.waitForTimeout(500);
  await expect(page.locator('#dropdown-user-name')).toHaveText('Khách');
  await expect(page.locator('body')).not.toContainText('support-secret-message');
  expect(await page.evaluate(() => sessionStorage.getItem('pbl3_support_threads'))).toBeNull();
  await expect(page.locator('#admin-panel')).toBeHidden();
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
