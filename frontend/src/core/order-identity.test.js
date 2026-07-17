import { describe, expect, it } from 'vitest';
import { getOrderUserId, orderBelongsToUserId } from './order-identity.js';

describe('order identity boundary', () => {
  const user = {
    id: 'user-customer-1',
    username: 'same-username',
    email: 'same@example.com',
    phone: '0900000000',
    name: 'Nguyen Van A'
  };

  it('accepts the matching immutable user id', () => {
    expect(orderBelongsToUserId({ userId: 'user-customer-1' }, user)).toBe(true);
    expect(orderBelongsToUserId({ accountKey: 'user-customer-1' }, user)).toBe(true);
  });

  it('does not associate same mutable contact data with a different user', () => {
    const anotherCustomerOrder = {
      userId: 'user-customer-2',
      customer: {
        username: user.username,
        email: user.email,
        phone: user.phone,
        name: user.name
      },
      address: { recipient: user.name, phone: user.phone },
      accountKeyAliases: [user.id]
    };

    expect(orderBelongsToUserId(anotherCustomerOrder, user)).toBe(false);
  });

  it('fails closed for missing or conflicting immutable ids', () => {
    expect(orderBelongsToUserId({ customer: user, accountKeyAliases: [user.id] }, user)).toBe(false);
    expect(getOrderUserId({ userId: 'user-customer-1', accountKey: 'user-customer-2' })).toBe('');
  });
});
