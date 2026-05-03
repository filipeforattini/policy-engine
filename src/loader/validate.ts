const VALID_EFFECTS = new Set(["allow", "deny", "audit"])

const VALID_OPERATORS = new Set([
  "==", "!=", "<", "<=", ">", ">=",
  "in", "notIn", "regex", "startsWith", "endsWith", "contains", "exists",
])

function loc(source: string, id: string | null, index: number): string {
  return id ? `${source}[${index}] (id: "${id}")` : `${source}[${index}]`
}

function isStringArray(val: unknown): val is string[] {
  return Array.isArray(val) && val.every((v) => typeof v === "string")
}

function validateMatchNode(node: unknown, path: string, at: string): void {
  if (node === null || typeof node !== "object") {
    throw new Error(`${at} — ${path} must be an object, got ${JSON.stringify(node)}`)
  }

  const obj = node as Record<string, unknown>

  if ("allOf" in obj) {
    if (!Array.isArray(obj.allOf)) throw new Error(`${at} — ${path}.allOf must be an array`)
    obj.allOf.forEach((n, i) => validateMatchNode(n, `${path}.allOf[${i}]`, at))
    return
  }
  if ("anyOf" in obj) {
    if (!Array.isArray(obj.anyOf)) throw new Error(`${at} — ${path}.anyOf must be an array`)
    obj.anyOf.forEach((n, i) => validateMatchNode(n, `${path}.anyOf[${i}]`, at))
    return
  }
  if ("not" in obj) {
    validateMatchNode(obj.not, `${path}.not`, at)
    return
  }

  // Leaf record — each key is a dotted path, value is MatchValue
  for (const [key, value] of Object.entries(obj)) {
    if (!/^[a-zA-Z_][a-zA-Z0-9_.]*$/.test(key)) {
      throw new Error(`${at} — ${path} contains invalid path key "${key}" (must be a dotted identifier)`)
    }
    if (value !== null && typeof value === "object" && !Array.isArray(value)) {
      // Operator object — validate keys
      for (const opKey of Object.keys(value as object)) {
        if (!VALID_OPERATORS.has(opKey)) {
          throw new Error(`${at} — ${path}.${key} contains unknown operator "${opKey}"`)
        }
      }
    }
  }
}

export function validatePolicy(raw: unknown, source: string, index: number): void {
  if (raw === null || typeof raw !== "object" || Array.isArray(raw)) {
    throw new Error(`${loc(source, null, index)}: policy must be an object`)
  }

  const p = raw as Record<string, unknown>
  const id = typeof p.id === "string" ? p.id : null
  const at = loc(source, id, index)

  if (!id || id.trim() === "") {
    throw new Error(`${at}: "id" must be a non-empty string`)
  }
  if (typeof p.description !== "string" || p.description.trim() === "") {
    throw new Error(`${at}: "description" is required and must be a non-empty string`)
  }
  if (!VALID_EFFECTS.has(p.effect as string)) {
    throw new Error(`${at}: "effect" must be one of allow/deny/audit, got "${p.effect}"`)
  }
  if (!isStringArray(p.principals) || p.principals.length === 0) {
    throw new Error(`${at}: "principals" must be a non-empty array of strings`)
  }
  if (!isStringArray(p.actions) || p.actions.length === 0) {
    throw new Error(`${at}: "actions" must be a non-empty array of strings`)
  }
  if (!isStringArray(p.resources) || p.resources.length === 0) {
    throw new Error(`${at}: "resources" must be a non-empty array of strings`)
  }
  if (p.match !== undefined) {
    validateMatchNode(p.match, "match", at)
  }
}
