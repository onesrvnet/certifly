/**
 * Control characters (C0, DEL and C1). Names that reach config files or terminals must not hold
 * them: a line break in a host group name would start a new line in a generated ssh config, and
 * escape sequences in a host name would run in the terminal that prints it.
 */
const CONTROL = /\p{Cc}/u
const CONTROL_ALL = /\p{Cc}/gu

export const hasControlCharacters = (value: string) => CONTROL.test(value)
export const stripControlCharacters = (value: string) => value.replace(CONTROL_ALL, '')
