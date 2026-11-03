import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

const source = readFileSync(new URL('./main.js', import.meta.url), 'utf8');
const functions = [
  'getVoucherAssignmentQuantity', 'normalizeVoucherAssignmentGrant',
  'getVoucherAssignmentGrantList', 'normalizeVoucherAssignmentEntry',
  'getVoucherAssignmentStore', 'saveVoucherAssignmentStore', 'pruneExpiredVoucherAssignments',
  'applyVoucherAssignmentSyncResponse'
].map(name => {
  const start = source.indexOf(`    function ${name}(`);
  if (start < 0) throw new Error(`Missing storefront function: ${name}`);
  const next = /\n    (?:async )?function /.exec(source.slice(start + 1));
  if (!next) throw new Error(`Missing function boundary after: ${name}`);
  return source.slice(start, start + 1 + next.index);
}).join('\n');

// Execute the shipped cache functions without starting the DOM or making API calls.
function cacheFixture(stored, { version = 'current', expired = false } = {}) {
  return new Function('initial', 'version', 'expired', `
    const VOUCHER_ASSIGNMENTS_VERSION_KEY = 'version';
    const VOUCHER_ASSIGNMENTS_VERSION = 'current';
    const VOUCHER_ASSIGNMENTS_KEY = 'assignments';
    const DEFAULT_VOUCHER_ASSIGNMENT_QUANTITY = 1;
    const sanitizeProductText = value => String(value);
    let stored = initial, writes = 0;
    const readStoredValue = () => version;
    const readStorage = () => stored;
    const writeStorage = (key, value) => { stored = JSON.parse(JSON.stringify(value)); writes++; };
    const writeStoredValue = () => {};
    const removeStorage = () => { stored = null; };
    const getManagedVoucherCatalog = () => [{ code: 'SAFE' }];
    const isVoucherExpired = () => expired;
    const parseSyncPayload = response => JSON.parse(response.payload);
    ${functions}
    return {
      read: getVoucherAssignmentStore,
      save: saveVoucherAssignmentStore,
      prune: pruneExpiredVoucherAssignments,
      sync: applyVoucherAssignmentSyncResponse,
      persisted: () => stored,
      writes: () => writes
    };
  `)(stored, version, expired);
}

describe('voucher assignment dictionary boundary', () => {
  it.each(['__proto__', 'constructor', 'prototype', 'toString', 'customer-ordinary'])(
    'preserves %s as an own data key across read, save and expiry pruning', key => {
      const initial = JSON.parse(JSON.stringify({ entry: { accountKey: key, codes: ['SAFE'] } }));
      const fixture = cacheFixture(initial);
      const result = fixture.read();
      expect(Object.getPrototypeOf(result)).toBeNull();
      expect(Object.hasOwn(result, key)).toBe(true);
      expect(result[key].codes).toEqual(['SAFE']);
      fixture.save(result);
      expect(Object.hasOwn(fixture.persisted(), key)).toBe(true);
      const roundTrip = fixture.read();
      const pruned = fixture.prune(roundTrip);
      expect(Object.getPrototypeOf(pruned)).toBeNull();
      expect(Object.hasOwn(pruned, key)).toBe(true);
      expect(pruned[key].grants.SAFE.quantity).toBe(1);
      expect(Object.prototype.accountKey).toBeUndefined();
    }
  );

  it('removes expired grants and persists prototype-named keys without mutation', () => {
    const fixture = cacheFixture(JSON.parse('{"__proto__":{"codes":["SAFE"]}}'), { expired: true });
    const pruned = fixture.prune();
    expect(Object.getPrototypeOf(pruned)).toBeNull();
    expect(pruned.__proto__.codes).toEqual([]);
    expect(Object.hasOwn(fixture.persisted(), '__proto__')).toBe(true);
    expect(fixture.writes()).toBe(1);
  });

  it.each([null, [], 'invalid'])('returns a safe empty dictionary for invalid cache %j', value => {
    const result = cacheFixture(value).read();
    expect(Object.getPrototypeOf(result)).toBeNull();
    expect(Object.keys(result)).toEqual([]);
    expect(result.constructor).toBeUndefined();
  });

  it('keeps the version invalidation behavior and returns a safe empty dictionary', () => {
    const fixture = cacheFixture({ ordinary: { codes: ['SAFE'] } }, { version: 'old' });
    const result = fixture.read();
    expect(Object.getPrototypeOf(result)).toBeNull();
    expect(Object.keys(result)).toEqual([]);
    expect(fixture.persisted()).toBeNull();
  });

  it.each(['current', 'old'])('accepts assignment sync after an empty %s cache', version => {
    const fixture = cacheFixture(null, { version });
    expect(fixture.sync('__proto__', { payload: '{"codes":["SAFE"]}' })).toBe(true);
    expect(Object.hasOwn(fixture.persisted(), '__proto__')).toBe(true);
    expect(fixture.persisted().__proto__.codes).toEqual(['SAFE']);
  });

  it('preserves ordinary quantities, usage and legacy array grants', () => {
    const fixture = cacheFixture({
      customer: { grants: { SAFE: { quantity: 4, used: 2 } } },
      legacy: ['SAFE']
    });
    const result = fixture.prune();
    expect(result.customer.grants.SAFE).toMatchObject({ quantity: 4, used: 2 });
    expect(result.legacy.grants.SAFE).toMatchObject({ quantity: 1, used: 0 });
    fixture.save(result);
    expect(fixture.read().customer.grants.SAFE).toMatchObject({ quantity: 4, used: 2 });
  });
});
