import type { Resource } from "./types"

export function matchPattern(pattern: string, value: string): boolean {
  if (pattern === "*") return true
  if (pattern === value) return true
  if (!hasSpecial(pattern)) return false
  return globToRegex(pattern).test(value)
}

export function matchAny(values: string[], patterns: string[]): boolean {
  return values.some((value) =>
    patterns.some((pattern) => {
      if (matchPattern(pattern, value)) return true
      // Bidirectionality: a broader wildcard on the principal side satisfies a narrower policy pattern.
      // e.g. principal carries scope:lead.** → satisfies policy requiring scope:lead.read
      if (value !== "*" && hasSpecial(value)) return matchPattern(value, pattern)
      return false
    }),
  )
}

export function resourceMatches(patterns: string[], resource: Resource): boolean {
  const full = `${resource.type}:${resource.id}`
  const typeOnly = resource.type
  // Only test actual resource values — never synthetic wildcards like "lead:*"
  // which would cause false positives when policy patterns contain ? or [abc].
  return patterns.some((p) => matchPattern(p, full) || matchPattern(p, typeOnly))
}

// ── Internals ────────────────────────────────────────────────────────────────

function hasSpecial(s: string): boolean {
  return s.includes("*") || s.includes("?") || s.includes("{") || s.includes("[")
}

function escapeChar(ch: string): string {
  return /[.+^${}()|[\]\\]/.test(ch) ? `\\${ch}` : ch
}

function globToRegex(pattern: string): RegExp {
  let out = ""
  let i = 0

  while (i < pattern.length) {
    const ch = pattern[i]

    if (ch === "*" && pattern[i + 1] === "*") {
      // ** after a dot: foo.** → foo(\..*)? (zero-or-more dotted segments)
      if (out.endsWith("\\.")) {
        out = out.slice(0, -2) + "(\\..*)?";
      } else {
        out += ".*"
      }
      i += 2
    } else if (ch === "*") {
      out += "[^.]*"   // one segment — does not cross dots
      i++
    } else if (ch === "?") {
      out += "[^.]"    // one char — does not cross dots
      i++
    } else if (ch === "{") {
      const close = pattern.indexOf("}", i)
      if (close === -1) { out += "\\{"; i++; continue }
      const alts = pattern.slice(i + 1, close).split(",").map((a) =>
        a.trim().split("").map(escapeChar).join("")
      )
      out += `(${alts.join("|")})`
      i = close + 1
    } else if (ch === "[") {
      const close = pattern.indexOf("]", i)
      if (close === -1) { out += "\\["; i++; continue }
      out += pattern.slice(i, close + 1)   // pass [abc] straight to regex
      i = close + 1
    } else {
      out += escapeChar(ch)
      i++
    }
  }

  return new RegExp(`^${out}$`)
}
