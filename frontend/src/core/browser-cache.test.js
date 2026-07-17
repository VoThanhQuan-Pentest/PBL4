import { describe, expect, it } from 'vitest';
import {
  getCacheStorage,
  isPrivateCacheKey,
  purgeLegacySensitiveLocalStorage,
  readJsonCache,
  writeJsonCache
} from './browser-cache.js';

class MemoryStorage {
  #values = new Map();

  get length() {
    return this.#values.size;
  }

  key(index) {
    return Array.from(this.#values.keys())[index] ?? null;
  }

  getItem(key) {
    return this.#values.has(key) ? this.#values.get(key) : null;
  }

  setItem(key, value) {
    this.#values.set(String(key), String(value));
  }

  removeItem(key) {
    this.#values.delete(String(key));
  }
}

function createStorages() {
  return {
    localStorage: new MemoryStorage(),
    sessionStorage: new MemoryStorage()
  };
}

describe('browser cache boundary', () => {
  it('keeps identity, PII, support, orders and entitlements out of localStorage', () => {
    for (const key of [
      'pbl3_address_book_user-1',
      'pbl3_order_history_user-1',
      'pbl3_workspace_orders',
      'pbl3_support_threads',
      'pbl3_managed_reviews',
      'pbl3_managed_vouchers',
      'pbl3_category_registry',
      'pbl3_promo_hunt_campaigns',
      'pbl3_voucher_assignments',
      'pbl3_promo_hunt_claims',
      'pbl3_local_behavior_events',
      'pbl3_search_history_user-1'
    ]) {
      expect(isPrivateCacheKey(key)).toBe(true);
    }

    expect(isPrivateCacheKey('pbl3_cart_user-1')).toBe(false);
    expect(isPrivateCacheKey('pbl3_recommendation_cache_v1')).toBe(false);
  });

  it('routes private JSON caches to sessionStorage and public UI caches to localStorage', () => {
    const storages = createStorages();
    writeJsonCache('pbl3_support_threads', [{ text: 'private' }], storages);
    writeJsonCache('pbl3_cart_user-1', [{ productId: 'product-1' }], storages);

    expect(readJsonCache('pbl3_support_threads', [], storages)).toEqual([{ text: 'private' }]);
    expect(storages.localStorage.getItem('pbl3_support_threads')).toBeNull();
    expect(storages.sessionStorage.getItem('pbl3_support_threads')).not.toBeNull();
    expect(getCacheStorage('pbl3_cart_user-1', storages)).toBe(storages.localStorage);
  });

  it('purges legacy token, identity and private records instead of migrating them', () => {
    const storages = createStorages();
    storages.localStorage.setItem('pbl3_token', 'raw-jwt');
    storages.localStorage.setItem('pbl3_user', '{"role":"admin"}');
    storages.localStorage.setItem('pbl3_order_history_user-1', '[{}]');
    storages.localStorage.setItem('pbl3_managed_vouchers', '[{}]');
    storages.localStorage.setItem('pbl3_cart_user-1', '[{}]');

    expect(purgeLegacySensitiveLocalStorage(storages)).toEqual(expect.arrayContaining([
      'pbl3_token',
      'pbl3_user',
      'pbl3_order_history_user-1',
      'pbl3_managed_vouchers'
    ]));
    expect(storages.localStorage.getItem('pbl3_cart_user-1')).not.toBeNull();
    expect(storages.localStorage.getItem('pbl3_user')).toBeNull();
  });
});
