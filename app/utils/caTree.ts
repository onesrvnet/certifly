import type { CertificateAuthority } from '~/types/api'

/** One row of the CA tree: a CA, or a CA outside certifly that signed one (shown by its subject only). */
export type CaTreeRow =
  | { kind: 'ca'; key: string; depth: number; ca: CertificateAuthority }
  | { kind: 'outside'; key: string; depth: number; subject: string }

/**
 * Orders CAs as a tree from the flat list: children under their parent, alphabetically. An
 * externally signed CA hangs under the outside chain that signed it (root first), so an outside
 * root shows as the top of its imported chain. CAs whose parent is not in the list go to the top.
 */
export function caTree(cas: readonly CertificateAuthority[]): CaTreeRow[] {
  const byName = (a: CertificateAuthority, b: CertificateAuthority) => a.name.localeCompare(b.name)
  const ids = new Set(cas.map((ca) => ca.id))
  const children = new Map<string, CertificateAuthority[]>()
  for (const ca of cas) {
    if (!ca.parent_ca_id || !ids.has(ca.parent_ca_id)) continue
    children.set(ca.parent_ca_id, [...(children.get(ca.parent_ca_id) ?? []), ca])
  }

  // Outside issuers form their own small tree, keyed by the path of subjects from the root.
  interface Outside {
    subject: string
    path: string
    nested: Map<string, Outside>
    cas: CertificateAuthority[]
  }
  const outsideRoots = new Map<string, Outside>()
  const tops: CertificateAuthority[] = []
  for (const ca of cas) {
    if (ca.parent_ca_id && ids.has(ca.parent_ca_id)) continue
    const path = [...ca.chain_subjects].reverse()
    if (ca.signing !== 'external' || !path.length) {
      tops.push(ca)
      continue
    }
    let level = outsideRoots
    let node: Outside | undefined
    let key = ''
    for (const subject of path) {
      key += `/${subject}`
      node = level.get(subject) ?? { subject, path: key, nested: new Map(), cas: [] }
      level.set(subject, node)
      level = node.nested
    }
    node!.cas.push(ca)
  }

  const rows: CaTreeRow[] = []
  const addCa = (ca: CertificateAuthority, depth: number) => {
    rows.push({ kind: 'ca', key: ca.id, depth, ca })
    for (const child of (children.get(ca.id) ?? []).sort(byName)) addCa(child, depth + 1)
  }
  const addOutside = (node: Outside, depth: number) => {
    rows.push({ kind: 'outside', key: `outside:${node.path}`, depth, subject: node.subject })
    for (const nested of [...node.nested.values()].sort((a, b) => a.subject.localeCompare(b.subject))) addOutside(nested, depth + 1)
    for (const ca of node.cas.sort(byName)) addCa(ca, depth + 1)
  }
  for (const ca of tops.sort(byName)) addCa(ca, 0)
  for (const node of [...outsideRoots.values()].sort((a, b) => a.subject.localeCompare(b.subject))) addOutside(node, 0)
  return rows
}

/** A slug from a CA name: lowercase words joined by hyphens, as the server accepts. */
export function slugify(name: string): string {
  return name
    .normalize('NFKD')
    .replace(/[̀-ͯ]/g, '')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 64)
    .replace(/-+$/g, '')
}

/** The common name in an RFC 4514 subject such as `CN=Root, O=Acme`, for short labels. */
export function commonNameOf(dn: string): string {
  return /(?:^|,\s*)CN=((?:\\.|[^,])+)/.exec(dn)?.[1]?.replace(/\\(.)/g, '$1') ?? dn
}
