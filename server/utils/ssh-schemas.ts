import { z } from 'zod'

/** The settings a host group carries, shared by its create and update endpoints. */
export const sshHostGroupSettings = {
  description: z.string().max(1000).optional(),
  host_patterns: z.array(z.string().max(253)).max(100).optional(),
  user_ttl_default_seconds: z.number().int().optional(),
  user_ttl_max_seconds: z.number().int().optional(),
  user_extensions: z.array(z.string().max(64)).max(20).optional(),
  force_command: z.string().max(1024).nullable().optional(),
  source_address: z.array(z.string().max(64)).max(50).optional(),
  key_policy: z.enum(['any', 'sk', 'sk_attested']).optional(),
  host_ttl_seconds: z.number().int().optional(),
}

/** An authorized_keys line. */
export const sshPublicKeyLine = z.string().min(1).max(16_384)
