/**
 * Minimal ability engine. Each subject type registers rules mapping an action to a
 * predicate over (actor, subject). Unregistered actions are denied.
 */
export type Rule<A, S> = (actor: A, subject: S) => boolean

export class PolicySet<A, S, Action extends string> {
  constructor(private readonly rules: Record<Action, Rule<A, S>>) {}

  can(actor: A, action: Action, subject: S): boolean {
    return this.rules[action]?.(actor, subject) ?? false
  }

  /** All abilities for a subject, for sending to clients to drive UI state. */
  abilities(actor: A, subject: S): Record<Action, boolean> {
    const result = {} as Record<Action, boolean>
    for (const action of Object.keys(this.rules) as Action[]) {
      result[action] = this.can(actor, action, subject)
    }
    return result
  }
}
