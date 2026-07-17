/**
 * Immutable identity helpers for order ownership.
 *
 * These helpers intentionally reject every mutable customer attribute.  The
 * server is the authority for order access; the browser uses this only to keep
 * its private, per-tab cache from mixing records between signed-in users.
 */
function firstNonBlank(values) {
  return values
    .map(value => String(value || '').trim())
    .find(Boolean) || '';
}

export function getImmutableUserId(subject = {}) {
  return firstNonBlank([
    subject?.userId,
    subject?.user_id,
    subject?.id
  ]);
}

export function getOrderUserId(order = {}, meta = {}) {
  const explicitUserId = firstNonBlank([
    order?.userId,
    order?.user_id
  ]);
  const compatibilityAccountKey = firstNonBlank([
    order?.accountKey,
    order?.account_key
  ]);

  // The current API sends both values with the same immutable value.  A
  // mismatch is unsafe and must not be attributed to either account.
  if (explicitUserId && compatibilityAccountKey && explicitUserId !== compatibilityAccountKey) {
    return '';
  }

  return explicitUserId || compatibilityAccountKey || firstNonBlank([
    meta?.userId,
    meta?.user_id
  ]);
}

export function orderBelongsToUserId(order, user) {
  const userId = getImmutableUserId(user);
  const orderUserId = getOrderUserId(order);
  return Boolean(userId && orderUserId && userId === orderUserId);
}
