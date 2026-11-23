// The server is type-checked against lib.webworker, which leaves out these WebCrypto key
// descriptions. packages/pki and packages/keyvault are written against lib.dom, where they
// exist; these copies match lib.dom so the server can type-check those packages too.
interface EcKeyAlgorithm extends KeyAlgorithm {
  namedCurve: NamedCurve
}

interface RsaKeyAlgorithm extends KeyAlgorithm {
  modulusLength: number
  publicExponent: BigInteger
}

interface RsaHashedKeyAlgorithm extends RsaKeyAlgorithm {
  hash: KeyAlgorithm
}
