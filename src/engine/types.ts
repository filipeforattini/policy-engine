export type PolicyEffect = "allow" | "deny" | "audit"

export type Principal = {
  id: string
  tenantId: string | null
  scopes: string[]
  groups: string[]
  attrs?: Record<string, unknown>
}

export type Resource = {
  type: string
  id: string
  tenantId: string | null
  attrs?: Record<string, unknown>
}

export type EvalContext = Record<string, unknown>

export type AuthzInput = {
  principal: Principal
  action: string
  resource: Resource
  context?: EvalContext
}

export type CandidatePolicy = {
  id: string
  description?: string
  effect: PolicyEffect
  requiredPrincipals: string[]
  missing: string[]
}

export type Decision = {
  allowed: boolean
  reason: "allow" | "explicit_deny" | "implicit_deny" | "tenant_mismatch"
  matchedPolicyIds: string[]
  auditedPolicyIds: string[]
  candidatePolicies: CandidatePolicy[]
}

export type PolicyCondition = (input: AuthzInput) => boolean

export type Policy = {
  id: string
  description?: string
  effect: PolicyEffect
  principals: string[]
  actions: string[]
  resources: string[]
  condition?: PolicyCondition
  _source?: string
  _index?: number
}

// JsonPolicy replaces the `condition` function with a declarative `match` object.
// Accepted by createAuthz alongside Policy — converted via compileMatch at load time.
// customCondition: a named TS function looked up from the customConditions map at load time.
export type JsonPolicy = Omit<Policy, "condition"> & {
  match?: import("./dsl").MatchNode
  customCondition?: string
}

export type RouteCheck = {
  action: string
  resolve?: (req: RequestLike) => Promise<Resource | Resource[]>
  mode?: "enforce" | "any" | "filter"
}

export type AuthzContext = {
  principal: Principal
  context?: EvalContext
  filtered?: Record<string, Resource[]>
}

export type RequestLike = {
  [key: string]: unknown
  authz?: AuthzContext
}
