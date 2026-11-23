// Pages that work without an account. `/setup` forwards the setup token to the sign-in page.
const isPublic = (path: string) => path === '/login' || path === '/setup' || path === '/invite' || path.startsWith('/auth/') || path.startsWith('/signin/')

export default defineNuxtRouteMiddleware(async (to) => {
  // Stores are looked up before the first await: after it the server has lost the Vue
  // context, and pinia would fall back to whichever request set the global store last.
  const auth = useAuthStore()

  if (to.path === '/setup') {
    return navigateTo({ path: '/login', query: typeof to.query.token === 'string' ? { setup_token: to.query.token } : {} })
  }

  if (!auth.loaded) await auth.load()

  if (!auth.user) {
    if (isPublic(to.path)) return
    return navigateTo({ path: '/login', query: to.fullPath === '/' ? {} : { redirect: to.fullPath } })
  }

  if (to.path === '/login') return navigateTo(safeRedirect(to.query.redirect))

  // Pages for some people only declare what they need (`definePageMeta({ requires })`); the
  // rest are sent to the no-access page instead of a half-loaded screen.
  const requires = to.meta.requires
  if (requires && !auth.can(requires[0], requires[1])) return navigateTo('/no-access', { replace: true })
})
