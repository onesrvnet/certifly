import { browserSupportsWebAuthn, browserSupportsWebAuthnAutofill, startAuthentication, startRegistration, WebAuthnAbortService } from '@simplewebauthn/browser'

import type { RpcOutput } from '~/types/api'

type Verified = RpcOutput<'passkey_sign_ins.verify'>['data']

/** The person dismissed the browser's passkey prompt (or another prompt replaced it). */
export function isPasskeyCancel(error: unknown) {
  return error instanceof Error && (error.name === 'NotAllowedError' || error.name === 'AbortError')
}

/**
 * Passkeys: create one for the signed-in account, and sign in with one. Browser prompts
 * that are dismissed throw an error `isPasskeyCancel` recognises.
 */
export function usePasskeys() {
  const rpc = useRpc()
  const { t } = useI18n()

  // Assumed until the browser says otherwise: nearly all do, and the server can't tell,
  // so this avoids flashing a "not supported" message on every load.
  const supported = ref(true)
  onMounted(() => {
    supported.value = browserSupportsWebAuthn()
  })

  /** A starting name for a new passkey from the device, e.g. "Chrome on macOS"; easy to rename. */
  function defaultName() {
    const ua = navigator.userAgent
    const browser = /Edg\//.test(ua) ? 'Edge' : /Firefox\//.test(ua) ? 'Firefox' : /Chrome\//.test(ua) ? 'Chrome' : /Safari\//.test(ua) ? 'Safari' : null
    const os = /iPhone|iPad/.test(ua) ? 'iOS' : /Android/.test(ua) ? 'Android' : /Mac OS X/.test(ua) ? 'macOS' : /Windows/.test(ua) ? 'Windows' : /Linux/.test(ua) ? 'Linux' : null
    return browser && os ? t('passkeys.defaultName', { browser, os }) : undefined
  }

  async function register(name?: string) {
    const { data: optionsJSON } = await rpc('passkey_registrations.create')
    const response = await startRegistration({ optionsJSON: optionsJSON as Parameters<typeof startRegistration>[0]['optionsJSON'] })
    return (await rpc('passkey_registrations.verify', { response, name })).data
  }

  /**
   * Sign in. With `autofill`, the passkey is offered in the email field's suggestions
   * instead of a dialog; the promise then waits until one is picked (or `cancel()`).
   */
  async function signIn(autofill = false): Promise<Verified> {
    const { data: optionsJSON } = await rpc('passkey_sign_ins.create')
    const response = await startAuthentication({
      optionsJSON: optionsJSON as Parameters<typeof startAuthentication>[0]['optionsJSON'],
      useBrowserAutofill: autofill,
    })
    return (await rpc('passkey_sign_ins.verify', { response })).data
  }

  /** Answer the options of `reauthentications.create` with a passkey and complete the re-authentication. */
  async function reauthenticate(optionsJSON: Parameters<typeof startAuthentication>[0]['optionsJSON']) {
    const response = await startAuthentication({ optionsJSON })
    return (await rpc('reauthentications.verify', { method: 'passkey', response })).data
  }

  return { supported, defaultName, reauthenticate, register, signIn, supportsAutofill: browserSupportsWebAuthnAutofill, cancel: () => WebAuthnAbortService.cancelCeremony() }
}
