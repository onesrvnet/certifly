import { index, pgEnum, pgTable, primaryKey, text, uniqueIndex, uuid } from 'drizzle-orm/pg-core'
import { sql } from 'drizzle-orm'
import { certificates, templates } from './certificates'
import { id, timestamps } from './columns'

/** The muted colours a tag chip can have. */
export const tagColor = pgEnum('tag_color', ['gray', 'blue', 'teal', 'green', 'yellow', 'orange', 'pink', 'violet'])

/** A label admins keep for grouping and filtering certificates. Names are unique regardless of case. */
export const tags = pgTable(
  'tags',
  {
    id: id(),
    name: text().notNull(),
    color: tagColor().notNull().default('gray'),
    ...timestamps,
  },
  (t) => [uniqueIndex('tags_name_lower_idx').on(sql`lower(${t.name})`)],
)

/** A template's default tags, copied onto each certificate it issues. */
export const templateTags = pgTable(
  'template_tags',
  {
    template_id: uuid()
      .notNull()
      .references(() => templates.id, { onDelete: 'cascade' }),
    tag_id: uuid()
      .notNull()
      .references(() => tags.id, { onDelete: 'cascade' }),
  },
  (t) => [primaryKey({ columns: [t.template_id, t.tag_id] }), index('template_tags_tag_idx').on(t.tag_id)],
)

/** The tags on a certificate. Set at issue, copied on renewal, edited by operators afterwards. */
export const certificateTags = pgTable(
  'certificate_tags',
  {
    certificate_id: uuid()
      .notNull()
      .references(() => certificates.id, { onDelete: 'cascade' }),
    tag_id: uuid()
      .notNull()
      .references(() => tags.id, { onDelete: 'cascade' }),
  },
  (t) => [primaryKey({ columns: [t.certificate_id, t.tag_id] }), index('certificate_tags_tag_idx').on(t.tag_id)],
)
