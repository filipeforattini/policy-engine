export type PolicyEffect = "allow" | "deny"

export type Principal = {
  id: string
  groups?: string[]
  scopes?: string[]
  roles?: string[]
  attrs?: Record<string, unknown>
}

export type Resource = {
  type: string
  id: string
  attrs?: Record<string, unknown>
}

export type EvalContext = Record<string, unknown>

export type AuthzInput = {
  principal: Principal
  action: string
  resource: Resource
  context?: EvalContext
}

export type Decision = {
  allowed: boolean
  reason: "allow" | "explicit_deny" | "implicit_deny"
  matchedPolicyIds: string[]
}

export type PolicyCondition = (input: AuthzInput) => boolean

export type RawPolicy = {
  id: string
  description?: string
  effect: PolicyEffect
  principals: string[]
  actions: string[]
  resources: string[]
  condition?: PolicyCondition
}

export type RouteCheck = {
  action: string
  resolve?: (req: RequestLike) => Promise<Resource>
  resolveMany?: (req: RequestLike) => Promise<Resource[]>
  mode?: "all" | "any" | "filter"
}

export type RouteChecksInput = (
  | RouteCheck
  | ((req: RequestLike) => Promise<RouteCheck[]>)
) &
  Record<string, unknown>

export type RouteChecksResult = {
  check: RouteCheck
  resource: Resource
  decision: Decision
}

export type AuthzContext = {
  principal: Principal
  context?: EvalContext
  filtered?: Record<string, Resource[]>
}

export type RequestLike = {
  [key: string]: unknown
  authz?: AuthzContext
  user?: Principal
}

type RequestWithAuthz = RequestLike & {
  authz: AuthzContext
}

export function createAuthz(opts: { policies: RawPolicy[] }) {
  const compiled = compilePolicies(opts.policies)

  const compilePrincipalSet = (principal: Principal): string[] => {
    const base   = [principal.id, `user:${principal.id}`]
    const roles  = principal.roles?.map((r)  => `role:${r}`)  ?? []
    const groups = principal.groups?.map((g) => `group:${g}`) ?? []
    const scopes = principal.scopes?.map((s) => `scope:${s}`) ?? []
    return [...base, ...roles, ...groups, ...scopes, "*"]
  }

  function evaluate(input: AuthzInput): Decision {
    const principalSet = compilePrincipalSet(input.principal)
    const applicable = compiled.filter((policy) => {
      if (!matchAny(principalSet, policy.principals)) return false
      if (!matchAny([input.action], policy.actions)) return false
      if (!resourceMatches(policy.resources, input.resource)) return false
      if (policy.condition && !policy.condition(input)) return false
      return true
    })

    const denies = applicable.filter((p) => p.effect === "deny")
    if (denies.length > 0) {
      return {
        allowed: false,
        reason: "explicit_deny",
        matchedPolicyIds: denies.map((p) => p.id),
      }
    }

    const allows = applicable.filter((p) => p.effect === "allow")
    if (allows.length > 0) {
      return {
        allowed: true,
        reason: "allow",
        matchedPolicyIds: allows.map((p) => p.id),
      }
    }

    return {
      allowed: false,
      reason: "implicit_deny",
      matchedPolicyIds: [],
    }
  }

  function attachContext({
    getPrincipal,
    getContext,
  }: {
    getPrincipal: (req: RequestLike) => Principal
    getContext?: (req: RequestLike) => EvalContext
  }) {
    return (req: RequestLike, _res: any, next: () => void) => {
      req.authz = {
        principal: getPrincipal(req),
        context: getContext?.(req),
        filtered: {},
      }
      next()
    }
  }

  function authorize(checks: RouteCheck[]) {
    return async (req: RequestLike, res: any, next: () => void) => {
      const principal = req.authz?.principal ?? req.user
      if (!principal) {
        return res.status(401).json({ error: "missing_principal" })
      }

      const context = req.authz?.context ?? {}
      const failures: RouteChecksResult[] = []

      for (const check of checks) {
        const mode = check.mode ?? "all"
        const resources = await resolveResources(check, req)
        const results = resources.map((resource) => ({
          check,
          resource,
          decision: evaluate({
            principal,
            action: check.action,
            resource,
            context,
          }),
        }))

        if (mode === "all") {
          for (const result of results) {
            if (!result.decision.allowed) {
              failures.push(result)
            }
          }
        }

        if (mode === "any") {
          const anyAllowed = results.some((r) => r.decision.allowed)
          if (!anyAllowed) {
            failures.push(...results)
          }
        }

        if (mode === "filter") {
          const allowedOnly = results
            .filter((r) => r.decision.allowed)
            .map((r) => r.resource)
          const reqWithAuthz = req as { authz?: AuthzContext } & RequestLike
          if (!reqWithAuthz.authz) {
            reqWithAuthz.authz = { principal: principal }
          }
          if (!reqWithAuthz.authz.filtered) {
            reqWithAuthz.authz.filtered = {}
          }
          reqWithAuthz.authz.filtered[makeFilterKey(check)] = allowedOnly
        }
      }

      if (failures.length > 0) {
        return res.status(403).json({
          error: "forbidden",
          failures: failures.map((f) => ({
            action: f.check.action,
            resource: { type: f.resource.type, id: f.resource.id },
            reason: f.decision.reason,
            matchedPolicyIds: f.decision.matchedPolicyIds,
          })),
        })
      }

      return next()
    }
  }

  async function authorizeRoute(
    checkFactory: (req: RequestLike) => Promise<RouteCheck[]> | RouteCheck[],
  ) {
    return async (req: RequestLike, res: any, next: () => void) => {
      const checks = await checkFactory(req)
      return authorize(checks)(req, res, next)
    }
  }

  return {
    evaluate,
    authorize,
    authorizeRoute,
    attachContext,
    policies: compiled,
  }
}

function makeFilterKey(check: RouteCheck) {
  return `${check.action}`
}

async function resolveResources(
  check: RouteCheck,
  req: RequestLike,
): Promise<Resource[]> {
  if (check.resolveMany) {
    return check.resolveMany(req)
  }
  if (check.resolve) {
    const single = await check.resolve(req)
    return [single]
  }
  return []
}

function compilePolicies(raw: RawPolicy[]) {
  return raw.map((policy) => ({
    ...policy,
    principals: [...policy.principals],
    actions: [...policy.actions],
    resources: [...policy.resources],
    condition: policy.condition,
  }))
}

function matchAny(values: string[], patterns: string[]) {
  return values.some((value) => patterns.some((pattern) => matchPattern(pattern, value)))
}

function resourceMatches(patterns: string[], resource: Resource) {
  const resourceValues = [
    `${resource.type}:${resource.id}`,
    `${resource.type}:*`,
    `${resource.type}`,
  ]
  return resourceValues.some((value) => patterns.some((pattern) => matchPattern(pattern, value)))
}

function matchPattern(pattern: string, value: string) {
  if (pattern === "*") return true
  if (!pattern.includes("*")) return pattern === value

  const escaped = pattern.replace(/[.+?^${}()|[\]\\]/g, "\\$&")
  const regex = new RegExp(`^${escaped.replace(/\*/g, ".*")}$`)
  return regex.test(value)
}
