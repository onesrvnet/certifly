/**
 * Baseline security headers on every response. No page may be framed by another site
 * (clickjacking). Routes that serve files set a stricter policy of their own, which
 * replaces this one.
 */
export default defineEventHandler((event) => {
  setResponseHeaders(event, {
    'content-security-policy': "frame-ancestors 'none'; object-src 'none'; base-uri 'self'; form-action 'self'",
    'x-frame-options': 'DENY',
    'x-content-type-options': 'nosniff',
    'referrer-policy': 'strict-origin-when-cross-origin',
    'permissions-policy': 'camera=(), microphone=(), geolocation=(), payment=()',
    ...(env().URL.startsWith('https://') && { 'strict-transport-security': 'max-age=31536000' }),
  })
})
