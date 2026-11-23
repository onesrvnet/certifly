/**
 * The one re-authentication dialog of the app. Sensitive actions answer `reauth_required`
 * until the person confirms it is them again; `request()` opens the dialog and resolves to
 * whether they did, so the caller can retry what it was doing.
 */
export const useReauthStore = defineStore('reauth', () => {
  const open = ref(false)
  let waiting: Promise<boolean> | null = null
  let settle: ((confirmed: boolean) => void) | null = null

  /** Open the dialog; several callers at once share it. */
  function request(): Promise<boolean> {
    if (waiting) return waiting
    open.value = true
    waiting = new Promise<boolean>((resolve) => {
      settle = resolve
    })
    return waiting
  }

  /** Close the dialog and tell the callers whether the person confirmed. */
  function finish(confirmed: boolean) {
    open.value = false
    settle?.(confirmed)
    settle = null
    waiting = null
  }

  return { open, request, finish }
})

