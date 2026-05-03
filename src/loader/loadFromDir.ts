import fs from "fs"
import path from "path"
import type { JsonPolicy, Policy, PolicyCondition } from "../engine/types"
import { compileMatch } from "../engine/dsl"
import { jsonPolicyToPolicy } from "../engine/createAuthz"
import { validatePolicy } from "./validate"

export type LoadOptions = {
  dir: string
  customConditions?: Record<string, PolicyCondition>
  extraPolicies?: Policy[]
}

export type LoadResult = {
  policies: Policy[]
  json: JsonPolicy[]
}

export function loadPoliciesFromDir(opts: LoadOptions): LoadResult {
  const { dir, customConditions = {}, extraPolicies = [] } = opts

  const files = fs
    .readdirSync(dir)
    .filter((f) => f.endsWith(".json"))
    .sort()

  const json: JsonPolicy[] = []

  for (const file of files) {
    const source = file.replace(/\.json$/, "")
    const fullPath = path.join(dir, file)
    let parsed: unknown

    try {
      parsed = JSON.parse(fs.readFileSync(fullPath, "utf-8"))
    } catch (e) {
      throw new Error(`Failed to parse ${file}: ${(e as Error).message}`)
    }

    if (!Array.isArray(parsed)) {
      throw new Error(`${file}: top-level value must be a JSON array of policies`)
    }

    parsed.forEach((raw, index) => {
      validatePolicy(raw, source, index)
      json.push({ ...(raw as JsonPolicy), _source: source, _index: index })
    })
  }

  const policies: Policy[] = json.map((jp) => {
    const raw = jp as JsonPolicy & { customCondition?: string }

    // Escape hatch: customCondition name → look up from provided map
    if ("customCondition" in raw && raw.customCondition) {
      const name = raw.customCondition
      const fn = customConditions[name]
      if (!fn) {
        throw new Error(
          `${raw._source}[${raw._index}] (id: "${raw.id}"): customCondition "${name}" not found in provided map`
        )
      }
      const { customCondition: _, match: __, ...rest } = raw as typeof raw & { match?: unknown }
      return { ...rest, condition: fn } as Policy
    }

    return jsonPolicyToPolicy(jp)
  })

  return {
    policies: [...policies, ...extraPolicies],
    json,
  }
}
