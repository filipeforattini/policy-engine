import type { Authz } from "../engine/createAuthz"
import type { Resource, RouteCheck, RequestLike } from "../engine/types"

type ChecksOrFactory = RouteCheck[] | ((req: RequestLike) => Promise<RouteCheck[]>)

type ForbiddenFailure = {
  action: string
  resource: { type: string; id: string }
  reason: string
  matchedPolicyIds: string[]
  candidatePolicies: { id: string; missing: string[] }[]
}

export function authorize(authz: Authz, checksOrFactory: ChecksOrFactory) {
  return async function authorizeMiddleware(
    req: RequestLike,
    res: ResponseLike,
    next: (err?: unknown) => void,
  ): Promise<void> {
    // 401 — no principal attached
    if (!req.authz?.principal) {
      res.status(401).json({ error: "missing_principal" })
      return
    }

    const { principal, context } = req.authz
    const checks = typeof checksOrFactory === "function"
      ? await checksOrFactory(req)
      : checksOrFactory

    const failures: ForbiddenFailure[] = []

    for (const check of checks) {
      const mode = check.mode ?? "enforce"
      const raw = check.resolve ? await check.resolve(req) : []
      const resources: Resource[] = Array.isArray(raw) ? raw : [raw]

      if (mode === "filter") {
        const allowed = resources.filter((resource) => {
          const decision = authz.evaluate({ principal, action: check.action, resource, context })
          return decision.allowed
        })
        req.authz.filtered ??= {}
        req.authz.filtered[check.action] = allowed
        continue
      }

      if (mode === "enforce") {
        for (const resource of resources) {
          const decision = authz.evaluate({ principal, action: check.action, resource, context })
          if (!decision.allowed) {
            failures.push({
              action: check.action,
              resource: { type: resource.type, id: resource.id },
              reason: decision.reason,
              matchedPolicyIds: decision.matchedPolicyIds,
              candidatePolicies: decision.candidatePolicies.map((c) => ({
                id: c.id,
                missing: c.missing,
              })),
            })
          }
        }
      }

      if (mode === "any") {
        const anyAllowed = resources.some((resource) => {
          const decision = authz.evaluate({ principal, action: check.action, resource, context })
          return decision.allowed
        })
        if (!anyAllowed && resources.length > 0) {
          const first = resources[0]
          const decision = authz.evaluate({ principal, action: check.action, resource: first, context })
          failures.push({
            action: check.action,
            resource: { type: first.type, id: first.id },
            reason: decision.reason,
            matchedPolicyIds: decision.matchedPolicyIds,
            candidatePolicies: decision.candidatePolicies.map((c) => ({
              id: c.id,
              missing: c.missing,
            })),
          })
        }
      }
    }

    if (failures.length > 0) {
      res.status(403).json({
        error: "forbidden",
        principal: {
          id: principal.id,
          tenantId: principal.tenantId,
          scopes: principal.scopes,
          groups: principal.groups,
        },
        failures,
      })
      return
    }

    next()
  }
}

// Minimal response interface — framework-agnostic stub target
export type ResponseLike = {
  status: (code: number) => ResponseLike
  json: (body: unknown) => void
}
