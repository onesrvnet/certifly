import type { KeyAlgorithm, KeygenInput } from '~/types/api'

export const MIN_PKCS12_PASSWORD = 12

/** Where the key for a new certificate comes from, as the issue and renew forms edit it. */
export interface KeySourceState {
  /** `reuse`: the CSR stored with the certificate being renewed. */
  mode: 'csr' | 'keygen' | 'reuse'
  csr: string
  algorithm: KeyAlgorithm
  format: 'pem' | 'pkcs12'
  password: string
  confirm: string
}

export function emptyKeySource(mode: KeySourceState['mode'], algorithm: KeyAlgorithm = 'ecdsa-p256'): KeySourceState {
  return { mode, csr: '', algorithm, format: 'pem', password: '', confirm: '' }
}

export function keySourceReady(state: KeySourceState): boolean {
  if (state.mode === 'reuse') return true
  if (state.mode === 'csr') return state.csr.includes('-----BEGIN')
  if (state.format === 'pkcs12') return state.password.length >= MIN_PKCS12_PASSWORD && state.password === state.confirm
  return true
}

/** The request fields for the chosen key source. */
export function keySourceRequest(state: KeySourceState): { csr?: string; keygen?: KeygenInput } {
  if (state.mode === 'csr') return { csr: state.csr }
  if (state.mode === 'keygen') {
    return { keygen: { algorithm: state.algorithm, format: state.format, ...(state.format === 'pkcs12' ? { pkcs12_password: state.password } : {}) } }
  }
  return {}
}
