/**
 * Encode an untrusted value for text or quoted HTML-attribute context.
 * Dynamic markup in the legacy UI must use this helper instead of inserting
 * API or localStorage values directly into an HTML template literal.
 */
export function escapeHtml(value) {
  return String(value ?? '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

/**
 * Allow only application-relative image paths or explicit HTTPS URLs.
 * This deliberately rejects data:, javascript:, protocol-relative and control
 * character sources before they can be interpolated into an image attribute.
 */
export function isSafeImageSource(value, origin = 'https://flarefitness.invalid') {
  const source = String(value ?? '').trim();
  if (!source || source.length > 500 || source.startsWith('//') || /[\\<>"'\u0000-\u001f]/.test(source)) {
    return false;
  }

  const lowerSource = source.toLowerCase();
  if (lowerSource.startsWith('javascript:') || lowerSource.startsWith('data:')) {
    return false;
  }

  if (source.startsWith('./') || source.startsWith('/') || source.startsWith('assets/')) {
    return true;
  }

  try {
    const url = new URL(source, origin);
    return url.protocol === 'https:'
      && source.startsWith('https://')
      && !url.username
      && !url.password;
  } catch {
    return false;
  }
}

/**
 * A class token is not text or a URL.  Keep it in its own narrow allowlist so
 * a future API field cannot inject attributes into a template literal.
 */
export function safeClassToken(value, fallback = '') {
  const token = String(value ?? '').trim();
  return /^[A-Za-z0-9_-]{1,80}$/.test(token) ? token : fallback;
}
