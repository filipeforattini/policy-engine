import type { AuthzInput, CandidatePolicy, Decision, Policy } from "./types"
import { matchAny, resourceMatches } from "./match"

export function compilePrincipalSet(principal: AuthzInput["principal"]): string[] {
  return [
    principal.id,
    `user:${principal.id}`,
    ...principal.scopes.map((s) => `scope:${s}`),
    ...principal.groups.map((g) => `group:${g}`),
    "*",
  ]
}

export function evaluate(input: AuthzInput, policies: Policy[]): Decision {
  // Tenant guard: runs before any policy. Principals with tenantId can only act
  // on resources of the same tenant. null on either side = cross-tenant allowed
  // (platform principals and global resources bypass this check).
  const pTenant = input.principal.tenantId
  const rTenant = input.resource.tenantId
  if (pTenant !== null && rTenant !== null && pTenant !== rTenant) {
    return {
      allowed: false,
      reason: "tenant_mismatch",
      matchedPolicyIds: [],
      auditedPolicyIds: [],
      candidatePolicies: [],
    }
  }

  const principalSet = compilePrincipalSet(input.principal)

  const allows: Policy[] = []
  const denies: Policy[] = []
  const audits: Policy[] = []
  const candidates: Policy[] = []

  for (const policy of policies) {
    const actionOk   = matchAny([input.action], policy.actions)
    const resourceOk = resourceMatches(policy.resources, input.resource)

    if (!actionOk || !resourceOk) continue

    const principalOk  = matchAny(principalSet, policy.principals)
    const conditionOk  = policy.condition ? policy.condition(input) : true
    const fullyMatches = principalOk && conditionOk

    if (policy.effect === "audit") {
      if (fullyMatches) audits.push(policy)
      continue
    }

    if (fullyMatches) {
      if (policy.effect === "deny")  denies.push(policy)
      else                           allows.push(policy)
    } else {
      candidates.push(policy)
    }
  }

  const auditedPolicyIds = audits.map((p) => p.id)

  if (denies.length > 0) {
    return {
      allowed: false,
      reason: "explicit_deny",
      matchedPolicyIds: denies.map((p) => p.id),
      auditedPolicyIds,
      candidatePolicies: [],
    }
  }

  if (allows.length > 0) {
    return {
      allowed: true,
      reason: "allow",
      matchedPolicyIds: allows.map((p) => p.id),
      auditedPolicyIds,
      candidatePolicies: [],
    }
  }

  return {
    allowed: false,
    reason: "implicit_deny",
    matchedPolicyIds: [],
    auditedPolicyIds,
    candidatePolicies: candidates.map((p) => buildCandidate(p, principalSet, input)),
  }
}

function buildCandidate(policy: Policy, principalSet: string[], input: AuthzInput): CandidatePolicy {
  const missing: string[] = []
  if (!matchAny(principalSet, policy.principals)) {
    missing.push(`principal — need one of: ${policy.principals.join(", ")}`)
  } else if (policy.condition && !policy.condition(input)) {
    missing.push("condition did not match")
  }
  return {
    id: policy.id,
    description: policy.description,
    effect: policy.effect,
    requiredPrincipals: [...policy.principals],
    missing,
  }
}
