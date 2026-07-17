/**
 * Browser cache boundary.
 *
 * `localStorage` is deliberately reserved for non-sensitive presentation data
 * (for example a cart's product identifiers or UI preferences).  Identity,
 * addresses, orders, support conversations, entitlements and behavioural
 * events are kept only for the current tab in sessionStorage.  None of these
 * caches are an authority; the API remains the source of truth.
 */

const PRIVATE_EXACT_KEYS = new Set([
  'pbl3_account_registry',
  'pbl3_analytics_session',
  'pbl3_local_behavior_events',
  'pbl3_managed_reviews',
  'pbl3_managed_vouchers',
  'pbl3_managed_vouchers_version',
  'pbl3_category_registry',
  'pbl3_promo_hunt_campaigns',
  'pbl3_promo_hunt_version',
  'pbl3_support_threads',
  'pbl3_voucher_assignments',
  'pbl3_voucher_assignments_version',
  'pbl3_workspace_orders'
]);

const PRIVATE_PREFIXES = [
  'pbl3_address_book_',
  'pbl3_order_history_',
  'pbl3_promo_hunt_claims',
  'pbl3_search_history_',
  'pbl3_voucher_'
];

export function isPrivateCacheKey(key) {
  const normalizedKey = String(key ?? '');
  return PRIVATE_EXACT_KEYS.has(normalizedKey)
    || PRIVATE_PREFIXES.some(prefix => normalizedKey.startsWith(prefix));
}

export function getCacheStorage(key, storages = globalThis) {
  return isPrivateCacheKey(key) ? storages.sessionStorage : storages.localStorage;
}

export function readCacheValue(key, fallback = null, storages = globalThis) {
  try {
    const raw = getCacheStorage(key, storages)?.getItem(String(key));
    return raw === null || raw === undefined ? fallback : raw;
  } catch {
    return fallback;
  }
}

export function readJsonCache(key, fallback = null, storages = globalThis) {
  const raw = readCacheValue(key, null, storages);
  if (!raw) {
    return fallback;
  }

  try {
    return JSON.parse(raw);
  } catch {
    return fallback;
  }
}

export function writeCacheValue(key, value, storages = globalThis) {
  try {
    getCacheStorage(key, storages)?.setItem(String(key), String(value));
    return true;
  } catch {
    return false;
  }
}

export function writeJsonCache(key, value, storages = globalThis) {
  try {
    return writeCacheValue(key, JSON.stringify(value), storages);
  } catch {
    return false;
  }
}

export function removeCacheValue(key, storages = globalThis) {
  try {
    getCacheStorage(key, storages)?.removeItem(String(key));
    return true;
  } catch {
    return false;
  }
}

/**
 * Removes legacy sensitive values that older frontend releases put in
 * localStorage.  We intentionally do not migrate these values: an old local
 * value must never be trusted as an account, order, entitlement or message.
 */
export function purgeLegacySensitiveLocalStorage(storages = globalThis) {
  const local = storages.localStorage;
  if (!local) {
    return [];
  }

  const removed = [];
  for (let index = local.length - 1; index >= 0; index -= 1) {
    const key = local.key(index);
    if (!key) {
      continue;
    }

    if (key === 'pbl3_token' || key === 'pbl3_user' || isPrivateCacheKey(key)) {
      local.removeItem(key);
      removed.push(key);
    }
  }
  return removed;
}
