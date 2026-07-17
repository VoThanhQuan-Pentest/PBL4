import { describe, expect, it } from 'vitest';
import { escapeHtml, isSafeImageSource, safeClassToken } from './dom-safety.js';

describe('DOM safety helpers', () => {
  it('renders hostile product, review, address, support and username text as text', () => {
    const payload = `<img src=x onerror="globalThis.pwned=1">'\"&`;

    expect(escapeHtml(payload)).toBe('&lt;img src=x onerror=&quot;globalThis.pwned=1&quot;&gt;&#39;&quot;&amp;');
    expect(escapeHtml('javascript:alert(1)')).toBe('javascript:alert(1)');

    for (const field of ['product name', 'review', 'address', 'support message', 'username']) {
      const markup = `<p data-field="${field}">${escapeHtml(payload)}</p>`;
      expect(markup).not.toContain('<img src=x');
      expect(markup).toContain('&lt;img');
      expect(markup).not.toContain('onerror="globalThis.pwned=1"');
    }
  });

  it('only permits safe application-relative or HTTPS image sources', () => {
    expect(isSafeImageSource('./assets/product.webp')).toBe(true);
    expect(isSafeImageSource('/assets/product.webp')).toBe(true);
    expect(isSafeImageSource('https://images.example/product.webp')).toBe(true);

    for (const payload of [
      'javascript:alert(1)',
      'data:text/html,<svg onload=alert(1)>',
      '//attacker.example/image.webp',
      'http://attacker.example/image.webp',
      'https://attacker.example/\" onerror=alert(1)',
      'https://user:password@attacker.example/image.webp'
    ]) {
      expect(isSafeImageSource(payload)).toBe(false);
    }
  });

  it('does not allow untrusted values to become CSS classes', () => {
    expect(safeClassToken('fa-futbol')).toBe('fa-futbol');
    expect(safeClassToken('orange')).toBe('orange');
    expect(safeClassToken('x" onmouseover="globalThis.pwned=1')).toBe('');
    expect(safeClassToken('two classes')).toBe('');
  });
});
