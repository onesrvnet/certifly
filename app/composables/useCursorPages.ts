/**
 * Numbered pages over a cursor-paginated list: the cursor of every page visited is
 * kept, so "previous" goes back without the server knowing about page numbers.
 */
export function useCursorPages(pageSize: number) {
  const cursors = ref<(string | undefined)[]>([undefined])
  const index = ref(0)
  const cursor = computed(() => cursors.value[index.value])
  /** Position of the current page's first row, for "1–25 of 80". */
  const offset = computed(() => index.value * pageSize)

  function next(nextCursor: string | null | undefined) {
    if (!nextCursor) return
    cursors.value = [...cursors.value.slice(0, index.value + 1), nextCursor]
    index.value++
  }

  function previous() {
    if (index.value > 0) index.value--
  }

  /** Back to the first page, e.g. when a filter changes. */
  function reset() {
    cursors.value = [undefined]
    index.value = 0
  }

  return { cursor, offset, index, next, previous, reset }
}
