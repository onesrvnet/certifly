import { z } from 'zod'

/** Keyset pagination in: `cursor` is the `next_cursor` of the previous page. */
export const paginationSchema = {
  cursor: z.string().max(1000).optional(),
  limit: z.number().int().min(1).max(200).default(50),
}
