import type { Permissions, Session, User } from '~/types/api'

export const useAuthStore = defineStore('auth', () => {
  const rpc = useRpc()

  const user = ref<User | null>(null)
  const session = ref<Session | null>(null)
  /** What the current user may do, per object id, as the API last reported it. */
  const permissions = ref<Record<string, Permissions>>({})
  const loaded = ref(false)

  /**
   * Remember the `permissions` that API objects carry: in `data` itself, in arrays and
   * up to two levels down.
   */
  function remember(data: unknown, depth = 2) {
    if (Array.isArray(data)) return data.forEach((item) => remember(item, depth))
    if (!data || typeof data !== 'object') return
    const object = data as { id?: unknown; permissions?: unknown }
    if (typeof object.id === 'string' && object.permissions && typeof object.permissions === 'object') {
      permissions.value[object.id] = object.permissions as Permissions
    }
    if (depth > 0) for (const value of Object.values(object)) if (value && typeof value === 'object') remember(value, depth - 1)
  }

  /**
   * Whether the current user may perform `ability` on the object with `id`: a user, an
   * invite, or `'instance'` for what belongs to no single object (audit log, settings, people).
   */
  function can(id: string | undefined, ability: string) {
    return !!id && !!permissions.value[id]?.[ability]
  }

  function reset() {
    user.value = null
    session.value = null
    permissions.value = {}
  }

  /** Load the session; a 401 just means signed out. */
  async function load() {
    try {
      const res = await rpc('sessions.get')
      user.value = res.data.user
      session.value = res.data.session
      remember(res.data)
    } catch (error) {
      if (error instanceof RpcError && error.status === 401) reset()
      else throw error
    } finally {
      loaded.value = true
    }
  }

  async function logout() {
    await rpc('sessions.delete').catch(() => {})
    reset()
  }

  return { user, session, permissions, loaded, can, remember, load, logout }
})
