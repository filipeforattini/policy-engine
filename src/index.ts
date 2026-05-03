// Middleware
export { createAttachContext } from "./middleware/attachContext"
export { authorize } from "./middleware/authorize"
export type { ResponseLike } from "./middleware/authorize"

// Loader
export { loadPoliciesFromDir } from "./loader/loadFromDir"
export type { LoadOptions, LoadResult } from "./loader/loadFromDir"

// Engine
export { createAuthz, jsonPolicyToPolicy } from "./engine/createAuthz"
export type { Authz } from "./engine/createAuthz"
export { evaluate, compilePrincipalSet } from "./engine/evaluate"
export { matchPattern, matchAny, resourceMatches } from "./engine/match"

// Match DSL
export { compileMatch, resolvePath } from "./engine/dsl"
export type { MatchLiteral, MatchOperator, MatchNode, MatchValue } from "./engine/dsl"

// Types
export type {
  PolicyEffect,
  Principal,
  Resource,
  EvalContext,
  AuthzInput,
  CandidatePolicy,
  Decision,
  PolicyCondition,
  Policy,
  JsonPolicy,
  RouteCheck,
  AuthzContext,
  RequestLike,
} from "./engine/types"
