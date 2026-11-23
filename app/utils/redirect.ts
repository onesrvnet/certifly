/**
 * Only allow same-origin paths as post-login redirect targets. Browsers read `/\host`
 * like `//host`, and drop tabs and newlines inside URLs, so paths with a backslash or a
 * control character are refused too.
 */
export function safeRedirect(value: unknown): string {
  if (typeof value !== 'string' || !value.startsWith('/') || value.startsWith('//')) return '/'
  return /[\\\u0000-\u001f\u007f]/.test(value) ? '/' : value
}
