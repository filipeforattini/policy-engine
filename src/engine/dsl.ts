import type { AuthzInput, PolicyCondition } from "./types"

// ── Public types ─────────────────────────────────────────────────────────────

export type MatchLiteral = string | number | boolean | null

export type MatchOperator = Partial<{
  "==":         MatchLiteral | string    // string may be a @ref
  "!=":         MatchLiteral | string
  "<":          number | string
  "<=":         number | string
  ">":          number | string
  ">=":         number | string
  in:           MatchLiteral[] | string  // array or @ref → array
  notIn:        MatchLiteral[] | string
  regex:        string
  startsWith:   string
  endsWith:     string
  contains:     string
  exists:       boolean
}>

// A leaf value in a match record: literal, sigil string (@ref, !neg, *), or operator object.
export type MatchValue = MatchLiteral | MatchOperator

// Full match node — either a leaf record, allOf, anyOf, or not.
export type MatchNode =
  | { allOf: MatchNode[] }
  | { anyOf: MatchNode[] }
  | { not:   MatchNode }
  | Record<string, MatchValue>

// ── Path resolution ───────────────────────────────────────────────────────────

export function resolvePath(path: string, input: AuthzInput): unknown {
  const parts = path.split(".")
  const root  = parts[0]
  const rest  = parts.slice(1)

  if (root === "principal") {
    const p = input.principal
    if (rest[0] === "id")       return p.id
    if (rest[0] === "tenantId") return p.tenantId
    if (rest[0] === "scopes")   return p.scopes
    if (rest[0] === "groups")   return p.groups
    if (rest[0] === "attrs")    return rest[1] != null ? p.attrs?.[rest[1]] : p.attrs
    return undefined
  }

  if (root === "resource") {
    const r = input.resource
    if (rest[0] === "id")       return r.id
    if (rest[0] === "type")     return r.type
    if (rest[0] === "tenantId") return r.tenantId
    if (rest[0] === "attrs") {
      return rest[1] != null ? r.attrs?.[rest[1]] : r.attrs
    }
    // Shorthand: resource.<key> → resource.attrs.<key>
    if (rest[0] != null)        return r.attrs?.[rest[0]]
    return undefined
  }

  if (root === "context") {
    return rest[0] != null ? input.context?.[rest[0]] : input.context
  }

  return undefined
}

// ── Core comparison ───────────────────────────────────────────────────────────

function resolveOperand(value: string, input: AuthzInput): unknown {
  return value.startsWith("@") ? resolvePath(value.slice(1), input) : value
}

function arrayIncludes(haystack: unknown, needle: unknown): boolean {
  if (!Array.isArray(haystack)) return haystack === needle
  return haystack.includes(needle)
}

function compareLeaf(lval: unknown, rawValue: MatchValue, input: AuthzInput): boolean {
  // null → strict null check
  if (rawValue === null) return lval === null

  // Operator object
  if (typeof rawValue === "object" && rawValue !== null) {
    return applyOperator(lval, rawValue as MatchOperator, input)
  }

  if (typeof rawValue === "string") {
    // * → wildcard, always passes
    if (rawValue === "*") return true

    // Negation prefix
    if (rawValue.startsWith("!")) {
      const inner = rawValue.slice(1)
      return !compareLeaf(lval, inner.startsWith("@") ? (inner as MatchValue) : inner, input)
    }

    // @ref → resolve right-hand side
    if (rawValue.startsWith("@")) {
      const rval = resolvePath(rawValue.slice(1), input)
      if (Array.isArray(lval) && Array.isArray(rval)) {
        return lval.some((el) => (rval as unknown[]).includes(el))
      }
      if (Array.isArray(rval)) return (rval as unknown[]).includes(lval)
      if (Array.isArray(lval)) return (lval as unknown[]).includes(rval)
      return lval === rval
    }

    // String literal — but lval may be array (e.g. principal.groups includes "channel:c1")
    return arrayIncludes(lval, rawValue)
  }

  // number / boolean literal
  return arrayIncludes(lval, rawValue)
}

function applyOperator(lval: unknown, op: MatchOperator, input: AuthzInput): boolean {
  const known = new Set(["==", "!=", "<", "<=", ">", ">=", "in", "notIn",
    "regex", "startsWith", "endsWith", "contains", "exists"])

  for (const key of Object.keys(op)) {
    if (!known.has(key)) throw new Error(`match DSL: unknown operator "${key}"`)
  }

  if ("==" in op) {
    const rhs = typeof op["=="] === "string" && op["=="]!.startsWith("@")
      ? resolvePath(op["=="]!.slice(1), input) : op["=="]
    if (!arrayIncludes(lval, rhs)) return false
  }

  if ("!=" in op) {
    const rhs = typeof op["!="] === "string" && op["!="]!.startsWith("@")
      ? resolvePath(op["!="]!.slice(1), input) : op["!="]
    if (arrayIncludes(lval, rhs)) return false
  }

  if ("<" in op) {
    const rhs = typeof op["<"] === "string" && op["<"]!.startsWith("@")
      ? resolvePath(op["<"]!.slice(1), input) : op["<"]
    if (!(Number(lval) < Number(rhs))) return false
  }

  if ("<=" in op) {
    const rhs = typeof op["<="] === "string" && op["<="]!.startsWith("@")
      ? resolvePath(op["<="]!.slice(1), input) : op["<="]
    if (!(Number(lval) <= Number(rhs))) return false
  }

  if (">" in op) {
    const rhs = typeof op[">"] === "string" && op[">"]!.startsWith("@")
      ? resolvePath(op[">"]!.slice(1), input) : op[">"]
    if (!(Number(lval) > Number(rhs))) return false
  }

  if (">=" in op) {
    const rhs = typeof op[">="] === "string" && op[">="]!.startsWith("@")
      ? resolvePath(op[">="]!.slice(1), input) : op[">="]
    if (!(Number(lval) >= Number(rhs))) return false
  }

  if ("in" in op) {
    const rhs = typeof op.in === "string" && op.in.startsWith("@")
      ? resolvePath(op.in.slice(1), input) : op.in
    const arr = Array.isArray(rhs) ? rhs : [rhs]
    if (!arr.includes(lval as MatchLiteral)) return false
  }

  if ("notIn" in op) {
    const rhs = typeof op.notIn === "string" && op.notIn.startsWith("@")
      ? resolvePath(op.notIn.slice(1), input) : op.notIn
    const arr = Array.isArray(rhs) ? rhs : [rhs]
    if (arr.includes(lval as MatchLiteral)) return false
  }

  if ("regex" in op) {
    if (typeof lval !== "string") return false
    if (!new RegExp(op.regex!).test(lval)) return false
  }

  if ("startsWith" in op) {
    if (typeof lval !== "string") return false
    if (!lval.startsWith(op.startsWith!)) return false
  }

  if ("endsWith" in op) {
    if (typeof lval !== "string") return false
    if (!lval.endsWith(op.endsWith!)) return false
  }

  if ("contains" in op) {
    if (typeof lval !== "string") return false
    if (!lval.includes(op.contains!)) return false
  }

  if ("exists" in op) {
    const present = lval !== undefined
    if (op.exists !== present) return false
  }

  return true
}

// ── Compile ───────────────────────────────────────────────────────────────────

export function compileMatch(node: MatchNode): PolicyCondition {
  return (input: AuthzInput) => evalNode(node, input)
}

function evalNode(node: MatchNode, input: AuthzInput): boolean {
  if ("allOf" in node) {
    return (node as { allOf: MatchNode[] }).allOf.every((n) => evalNode(n, input))
  }
  if ("anyOf" in node) {
    return (node as { anyOf: MatchNode[] }).anyOf.some((n) => evalNode(n, input))
  }
  if ("not" in node) {
    return !evalNode((node as { not: MatchNode }).not, input)
  }

  // Leaf record: every key must pass
  const record = node as Record<string, MatchValue>
  for (const [path, value] of Object.entries(record)) {
    const lval = resolvePath(path, input)
    if (!compareLeaf(lval, value, input)) return false
  }
  return true
}
