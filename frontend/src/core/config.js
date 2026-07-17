export const API_BASE = '/api';
export const UNSAFE_HTTP_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

export const STORAGE_KEYS = Object.freeze({
  cart: 'pbl3_cart',
  wishlist: 'pbl3_wishlist',
  addressBook: 'pbl3_address_book',
  orderHistory: 'pbl3_order_history'
});
