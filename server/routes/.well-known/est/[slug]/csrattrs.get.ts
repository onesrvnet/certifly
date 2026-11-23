/**
 * EST: CSR attributes
 *
 * `GET /.well-known/est/<template-slug>/csrattrs` (RFC 7030 §4.5): certifly asks for no
 * particular attributes, so the answer is empty (204). The template's rules apply to whatever
 * the request holds.
 */
export default defineEstHandler(async (event) => {
  return sendNoContent(event)
})
