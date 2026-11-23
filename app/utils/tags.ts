/** The colours a tag may have; each maps to a `--tag-<colour>` token in main.css. */
export const TAG_COLORS = ['gray', 'blue', 'teal', 'green', 'yellow', 'orange', 'pink', 'violet'] as const
export type TagColor = (typeof TAG_COLORS)[number]

export interface TagRef {
  id: string
  name: string
  color: TagColor | string
}

const toneOf = (color: string) => `var(--tag-${TAG_COLORS.includes(color as TagColor) ? color : 'gray'})`

/** Only the tone, for elements that colour themselves with `--tag-tone` (dots). */
export function tagTone(color: string) {
  return { '--tag-tone': toneOf(color) }
}

/** Tint, outline and dot for a tag colour, from its token. */
export function tagStyle(color: string) {
  const tone = toneOf(color)
  return {
    '--tag-tone': tone,
    backgroundColor: `color-mix(in oklab, ${tone} 10%, transparent)`,
    borderColor: `color-mix(in oklab, ${tone} 45%, transparent)`,
  }
}
