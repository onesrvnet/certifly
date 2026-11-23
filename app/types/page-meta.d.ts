declare module '#app' {
  interface PageMeta {
    /** i18n key of the title shown in the page header. */
    titleKey?: string
    /** Pages that render their own header set this to false. */
    header?: boolean
    /** `[subject id, ability]` the signed-in person's permissions must include to open the page. */
    requires?: [string, string]
  }
}

export {}
