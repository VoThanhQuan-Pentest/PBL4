import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

const legacySource = readFileSync(new URL('./main.js', import.meta.url), 'utf8');

describe('legacy storefront security regressions', () => {
  it('does not restore a user, token or privileged UI state from localStorage', () => {
    expect(legacySource).toContain('let currentUser = null;');
    expect(legacySource).toContain('purgeLegacySensitiveLocalStorage(window);');
    expect(legacySource).not.toContain('normalizeUserProfile(readStorage(USER_KEY))');
    expect(legacySource).not.toContain('TOKEN_KEY');
    expect(legacySource).not.toContain('USER_KEY');
    expect(legacySource).not.toContain("identity.includes('user admin')");
    expect(legacySource).not.toContain("identity.includes('user staff')");
    expect(legacySource).not.toContain('Authorization: `Bearer ${token}`');
    expect(legacySource).toContain("return String(currentUser?.id || '').trim();");
  });

  it('keeps server operations server-authoritative when an API request fails', () => {
    expect(legacySource).not.toContain('backfillLocalOrdersToApi');
    expect(legacySource).not.toContain("appendSupportMessage(threadId, 'staff', content)");
    expect(legacySource).not.toContain("appendSupportMessage(thread.id, 'customer', content)");
    expect(legacySource).toContain('Không thể cập nhật đơn hàng khi phiên nhân viên chưa được máy chủ xác thực.');
  });

  it('does not write private customer and operations data to localStorage', () => {
    for (const legacyWrite of [
      "localStorage.setItem('pbl3_support_threads'",
      "localStorage.setItem('pbl3_managed_reviews'",
      "localStorage.setItem(LOCAL_ANALYTICS_EVENTS_KEY",
      'localStorage.setItem(storageKey, JSON.stringify(normalizedAddresses))',
      'localStorage.setItem(storageKey, JSON.stringify(normalizedOrders))'
    ]) {
      expect(legacySource).not.toContain(legacyWrite);
    }
    expect(legacySource).toContain("writeStorage('pbl3_support_threads'");
    expect(legacySource).toContain('writeStorage(LOCAL_ANALYTICS_EVENTS_KEY');
  });

  it('uses the shared safety helpers for dynamic product, voucher and image markup', () => {
    expect(legacySource).toContain('escapeHtml(getProductImageUrl(product))');
    expect(legacySource).toContain('data-voucher-apply="${escapeHtml(voucher.code)}"');
    expect(legacySource).toContain('safeClassToken(section.icon)');
  });

  it('uses the masked CSRF response token instead of the raw cookie value', () => {
    expect(legacySource).toContain("return String(await getCsrfToken() || '');");
    expect(legacySource).not.toContain("readCookie('XSRF-TOKEN')");
  });

  it('refreshes CSRF state across authentication transitions and never fails logout open', () => {
    const logoutSource = legacySource.slice(
      legacySource.indexOf("logoutLink.addEventListener('click'"),
      legacySource.indexOf("loginForm.addEventListener('submit'")
    );
    const loginSessionSource = legacySource.slice(
      legacySource.indexOf('function applyLoginSession'),
      legacySource.indexOf('function switchAuthOverlay')
    );

    expect(legacySource).toContain("import { getCsrfToken, resetCsrfToken } from '../core/csrf.js';");
    expect(loginSessionSource).toContain('resetCsrfToken();');
    expect(logoutSource).toContain('resetCsrfToken();');
    expect(logoutSource).toContain("showCenteredMessage(error?.message || 'Không thể đăng xuất. Vui lòng thử lại.', 'error');");
    expect(logoutSource).not.toContain('finally');
    expect(logoutSource.indexOf('clearSession();')).toBeGreaterThan(logoutSource.indexOf('catch (error)'));
  });

  it('invalidates privileged catalog loads and purges role-scoped state on logout', () => {
    const clearSessionSource = legacySource.slice(
      legacySource.indexOf('function purgeRoleScopedClientState'),
      legacySource.indexOf('async function placeOrder')
    );
    const loadProductsSource = legacySource.slice(
      legacySource.lastIndexOf('async function loadProducts'),
      legacySource.indexOf('function getBestSellerRows')
    );

    expect(clearSessionSource).toContain('catalogLoadGeneration += 1;');
    expect(clearSessionSource).toContain('allProducts = [];');
    expect(clearSessionSource).toContain('window.__pbl3WorkspaceState = null;');
    expect(clearSessionSource).toContain("document.querySelectorAll('.workspace-dynamic-panel')");
    expect(clearSessionSource).toContain('reloadPublicCatalogAfterSessionClear');
    expect(loadProductsSource).toContain('requestGeneration !== catalogLoadGeneration');
    expect(loadProductsSource).toContain("fetchProductsFromApi(manageProducts)");
  });

  it('fences asynchronous API and sync work to one authenticated browser context', () => {
    const apiSource = legacySource.slice(
      legacySource.indexOf('function captureAuthContext'),
      legacySource.indexOf('function parseSyncPayload')
    );
    const syncSource = legacySource.slice(
      legacySource.indexOf('function scheduleSyncStatePush'),
      legacySource.indexOf('function applyVoucherAssignmentSyncResponse')
    );

    expect(apiSource).toContain('authEpoch: acknowledgedAuthEpoch');
    expect(apiSource).toContain("acknowledgedAuthEpoch === String(readStoredValue(AUTH_EPOCH_KEY, '') || '')");
    expect(apiSource).toContain('if (auth && !isAuthContextCurrent(requestAuthContext))');
    expect(apiSource).toContain('response.status === 401 && auth && hasAuthenticatedSession()');
    expect(syncSource).toContain('const scheduledAuthContext = auth ? captureAuthContext() : null;');
    expect(syncSource).toContain('!isAuthContextCurrent(scheduledAuthContext)');
  });

  it('broadcasts account transitions and purges private tab state before reuse', () => {
    const transitionSource = legacySource.slice(
      legacySource.indexOf('function purgeRoleScopedClientState'),
      legacySource.indexOf('async function placeOrder')
    );

    expect(legacySource).toContain("if (event.key === AUTH_EPOCH_KEY)");
    expect(legacySource).toContain('void refreshSessionAfterExternalAuthChange();');
    expect(transitionSource).toContain('publishAuthEpoch();');
    expect(transitionSource).toContain('syncWriteTimers.forEach(timerId => window.clearTimeout(timerId));');
    expect(transitionSource).toContain("removeStorage('pbl3_support_threads');");
    expect(transitionSource).toContain("removeStorage('pbl3_managed_reviews');");
    expect(transitionSource).toContain('removeStorage(LOCAL_ANALYTICS_EVENTS_KEY);');
    expect(transitionSource).toContain('[window.localStorage, window.sessionStorage].forEach');
    expect(transitionSource).toContain('profileForm?.reset();');
    expect(transitionSource).toContain('passwordForm?.reset();');
  });

  it('serializes every auth-cookie mutation across same-origin tabs', () => {
    const authEventSource = legacySource.slice(
      legacySource.indexOf("logoutLink.addEventListener('click'"),
      legacySource.indexOf("forgotPasswordForm.addEventListener('submit'")
    );
    const lockSource = legacySource.slice(
      legacySource.indexOf('async function withAuthCookieMutationLock'),
      legacySource.indexOf('function createStaleAuthContextError')
    );

    expect(legacySource).toContain("const AUTH_COOKIE_MUTATION_LOCK = 'pbl3-auth-cookie-mutation';");
    expect(lockSource).toContain('window.navigator?.locks');
    expect(lockSource).toContain("{ mode: 'exclusive' }");
    expect(authEventSource.match(/withAuthCookieMutationLock/g)).toHaveLength(3);
    expect(authEventSource).toContain('assertAuthContextCurrent(logoutAuthContext);');
    expect(authEventSource.indexOf('applyLoginSession(loginResponse);')).toBeLessThan(
      authEventSource.indexOf('return loginResponse;')
    );
  });

  it('discards stale recommendations, reviews, orders and support responses', () => {
    expect(legacySource).toContain('if (recommendationFetchPromises.get(cacheKey) === requestPromise)');
    expect(legacySource).toContain('homeRecommendationSignature !== signature');
    expect(legacySource).toContain('if (orderApiSyncPromise === syncPromise)');
    expect(legacySource).toContain('if (reviewApiSyncPromise === syncPromise)');
    expect(legacySource).toContain('if (!isAuthContextCurrent(requestAuthContext) || !requestAuthContext.workspaceAccess)');
    expect(legacySource).toContain('if (!isAuthContextCurrent(orderAuthContext))');
  });

  it('does not present manufactured reviews or a seed catalog as server data', () => {
    expect(legacySource).not.toContain('function buildSeedReviews');
    expect(legacySource).not.toContain('function buildSampleReviewsForProduct');
    expect(legacySource).not.toContain('function getExtendedSportProductsSeed');
    expect(legacySource).not.toContain('function getWorldCup2026KitProductsSeed');
    expect(legacySource).not.toContain('mergeWithExtendedSportProducts');
    expect(legacySource).toContain("productLoadError = 'Không thể tải danh mục sản phẩm từ máy chủ.");
    expect(legacySource).toContain("'Chưa có đánh giá'");
  });

  it('retires managed-review sync and strips public review metadata', () => {
    const appSyncSource = legacySource.slice(
      legacySource.indexOf('async function syncAppStateFromApi'),
      legacySource.indexOf('async function syncCurrentUserStateFromApi')
    );
    const reviewSource = legacySource.slice(
      legacySource.indexOf('function normalizePublicReviewRecord'),
      legacySource.indexOf('function normalizeSupportThreadRecord')
    );
    const publicNormalizerSource = reviewSource.slice(
      reviewSource.indexOf('function normalizePublicReviewRecord'),
      reviewSource.indexOf('function normalizeInternalReviewRecord')
    );

    expect(appSyncSource).not.toContain("key: 'managed-reviews'");
    expect(reviewSource).toContain('function normalizePublicReviewRecord');
    expect(publicNormalizerSource).toContain('status: REVIEW_STATUS_VISIBLE');
    expect(publicNormalizerSource).not.toContain('orderId:');
    expect(publicNormalizerSource).not.toContain('userId:');
    expect(reviewSource).toContain('.map(normalizePublicReviewRecord)');
  });

  it('sanitizes legacy review cache according to the current authority', () => {
    const reviewSource = legacySource.slice(
      legacySource.indexOf('function normalizePublicReviewRecord'),
      legacySource.indexOf('function normalizeSupportThreadRecord')
    );

    expect(reviewSource).toContain('function normalizeCachedReviewRecord');
    expect(reviewSource).toContain('hasAuthenticatedSession()');
    expect(reviewSource).toContain('isStaffWorkspaceUser()');
    expect(reviewSource).toContain('reviewUserId === currentUserId');
    expect(legacySource).toContain('let sessionRestoreComplete = false;');
    expect(legacySource).toContain('let sessionRestorePromise = null;');
    expect(legacySource).toContain('sessionRestoreComplete = true;');
    expect(legacySource).toContain('await ensureSessionRestored();');
    expect(reviewSource).toContain('if (!sessionRestoreComplete)');
  });

  it('links orders and customer summaries only through immutable user ids', () => {
    const ownershipSource = legacySource.slice(
      legacySource.indexOf('function orderBelongsToUser'),
      legacySource.indexOf('/* Removed duplicate isStaffWorkspaceUser')
    );
    const customerIndexSource = legacySource.slice(
      legacySource.indexOf('function buildCustomerIdentityIndex'),
      legacySource.indexOf('function isAccountDeletedWithRelatedData')
    );
    const orderNormalizerSource = legacySource.slice(
      legacySource.indexOf('function normalizeWorkspaceOrder'),
      legacySource.indexOf('function getWorkspaceOrdersStorageKey')
    );

    expect(legacySource).toContain("from '../core/order-identity.js';");
    expect(ownershipSource).toContain('return orderBelongsToUserId(order, user);');
    for (const mutableIdentity of [
      'accountKeyAliases',
      'customer.id',
      'customer.username',
      'customer.email',
      'customer.phone',
      'order.address?.recipient',
      'order.address?.phone',
      'includes('
    ]) {
      expect(ownershipSource).not.toContain(mutableIdentity);
    }

    expect(customerIndexSource).toContain('const userId = getAccountKeyForUser(account);');
    expect(customerIndexSource).toContain('const userId = getOrderUserId(order);');
    for (const mutableIdentity of [
      'username',
      'email',
      'phone',
      'sdt',
      'address',
      'accountKeyAliases',
      'user-customer-'
    ]) {
      expect(customerIndexSource).not.toContain(mutableIdentity);
    }

    expect(orderNormalizerSource).toContain('const userId = getOrderUserId(order, meta);');
    expect(orderNormalizerSource).not.toContain('getAccountKeyForUser(customer)');
    expect(orderNormalizerSource).not.toContain('accountKeyAliases');
  });
});
