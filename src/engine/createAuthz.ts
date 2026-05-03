import type { AuthzInput, Decision, JsonPolicy, Policy } from "./types"
import { evaluate as evaluateInput } from "./evaluate"
import { compileMatch } from "./dsl"

export type Authz = {
  evaluate: (input: AuthzInput) => Decision
  replacePolicies: (next: (Policy | JsonPolicy)[]) => void
  readonly policies: Policy[]
}

export function jsonPolicyToPolicy(jp: JsonPolicy): Policy {
  const { match, ...rest } = jp
  return match
    ? { ...rest, condition: compileMatch(match) }
    : rest
}

export function createAuthz(opts: { policies: (Policy | JsonPolicy)[] }): Authz {
  let catalog: Policy[] = opts.policies.map((p) =>
    "match" in p && p.match !== undefined ? jsonPolicyToPolicy(p as JsonPolicy) : p as Policy
  )

  return {
    evaluate: (input: AuthzInput): Decision => evaluateInput(input, catalog),
    replacePolicies: (next: (Policy | JsonPolicy)[]): void => {
      catalog = next.map((p) =>
        "match" in p && p.match !== undefined ? jsonPolicyToPolicy(p as JsonPolicy) : p as Policy
      )
    },
    get policies(): Policy[] { return catalog },
  }
}
