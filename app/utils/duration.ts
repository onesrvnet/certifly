export const DAY_SECONDS = 24 * 60 * 60

/** Whole days for a lifetime in seconds, for the forms that edit lifetimes in days. */
export const secondsToDays = (seconds: number) => Math.max(1, Math.round(seconds / DAY_SECONDS))
export const daysToSeconds = (days: number) => Math.round(days * DAY_SECONDS)
