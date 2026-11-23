import { toast } from 'vue-sonner'

import { RpcError } from './useRpc'

/** Translate an RPC error code into a user-facing message. */
export function useErrorMessage() {
  const { t, te } = useI18n()
  return (error: unknown) => {
    const code = error instanceof RpcError ? error.code : 'unknown'
    const params = error instanceof RpcError ? (error.params ?? {}) : {}
    return te(`errors.${code}`) ? t(`errors.${code}`, params) : t('errors.unknown')
  }
}

/**
 * Show an error as a toast. When the server wants the person to confirm it is them again,
 * the re-authentication dialog opens instead, and `retry` runs once they have.
 */
export function useErrorToast() {
  const message = useErrorMessage()
  const reauth = useReauthStore()
  const show = (error: unknown, retry?: () => unknown) => {
    if (!isReauthRequired(error)) {
      toast.error(message(error))
      return
    }
    void reauth.request().then(async (confirmed) => {
      if (!confirmed || !retry) return
      try {
        await retry()
      } catch (again) {
        toast.error(message(again))
      }
    })
  }
  return show
}
