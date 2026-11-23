/**
 * Whether to show ⌘ or Ctrl shortcuts. Decided from the request's user agent on the
 * server and kept in state, so SSR and hydration render the same label.
 */
export function useIsMac() {
  const userAgent = import.meta.server ? (useRequestHeader('user-agent') ?? '') : ''
  return useState('is-mac', () => /Mac|iPhone|iPad/.test(import.meta.server ? userAgent : navigator.userAgent))
}
