/** An async action that tracks whether it is running; see `useAction`. */
export interface Action<Args extends unknown[], Result> {
  (...args: Args): Promise<Result | undefined>
  /** True while the action runs; reactive, e.g. `:disabled="save.busy"`. */
  readonly busy: boolean
}

/**
 * Wrap an async user action (save, delete, invite, …): `busy` is true while it runs,
 * calls while it is still running are ignored, and errors are shown as a toast. When the
 * server first wants the person to confirm it is them, the re-authentication dialog opens
 * and the action runs again once they have. The action resolves to the function's result,
 * or undefined when it failed or was ignored.
 *
 * Loading data for display is not an action: keep a `loading` flag for skeletons.
 */
export function useAction<Args extends unknown[], Result>(fn: (...args: Args) => Promise<Result>): Action<Args, Result> {
  const showError = useErrorToast()
  const reauth = useReauthStore()
  const busy = ref(false)

  const action = async (...args: Args) => {
    if (busy.value) return undefined
    busy.value = true
    try {
      return await fn(...args)
    } catch (error) {
      if (!isReauthRequired(error)) {
        showError(error)
        return undefined
      }
      // Closing the dialog cancels the action; there is nothing to report.
      if (!(await reauth.request())) return undefined
      try {
        return await fn(...args)
      } catch (again) {
        showError(again)
        return undefined
      }
    } finally {
      busy.value = false
    }
  }
  // A getter over the ref, so templates and computeds reading `action.busy` track it.
  return Object.defineProperty(action, 'busy', { get: () => busy.value }) as Action<Args, Result>
}
