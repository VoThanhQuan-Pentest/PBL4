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
