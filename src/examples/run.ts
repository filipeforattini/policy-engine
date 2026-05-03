import path from "path"
import { createAuthz } from "../engine/createAuthz"
import { loadPoliciesFromDir } from "../loader/loadFromDir"
import { createAttachContext } from "../middleware/attachContext"
import { authorize } from "../middleware/authorize"
import type { ResponseLike } from "../middleware/authorize"
import { MATCH_DSL_POLICIES } from "./demo-policies"
import { CASES, MATCH_DSL_CASES } from "./cases"
import type { ExampleCase } from "./cases"
import type { AuthzInput, Decision, RequestLike } from "../engine/types"
import { PRINCIPALS } from "./principals"
import { RESOURCES } from "./resources"

// ── Helpers ───────────────────────────────────────────────────────────────────

function runSuite(
  label: string,
  cases: ExampleCase[],
  engine: { evaluate: (i: AuthzInput) => Decision },
): { passed: number; failed: number } {
  let passed = 0
  let failed = 0

  console.log(`\n=== ${label} ===\n`)

  for (const example of cases) {
    const decision = engine.evaluate({
      principal: example.principal,
      action: example.action,
      resource: example.resource,
    })

    const resultLabel = decision.allowed ? "ALLOW" : "DENY"
    const ok = decision.allowed === example.expectedAllowed
    const icon = ok ? "✓" : "✗"

    if (ok) passed++; else failed++

    console.log(`${icon} [${resultLabel}] ${example.label}`)

    if (!ok) {
      const expected = example.expectedAllowed ? "ALLOW" : "DENY"
      console.log(`    expected: ${expected}, got reason: ${decision.reason}`)
      console.log(`    matched:  ${decision.matchedPolicyIds.join(", ") || "—"}`)
    }

    if (decision.reason === "implicit_deny" && decision.candidatePolicies.length > 0) {
      console.log(
        `    candidates: ${decision.candidatePolicies
          .map((c) => `${c.id} [missing: ${c.missing.join("; ")}]`)
          .join(" | ")}`,
      )
    }

    if (decision.auditedPolicyIds.length > 0) {
      console.log(`    audited: [${decision.auditedPolicyIds.join(", ")}]`)
    }
  }

  return { passed, failed }
}

// ── Load canonical policies from JSON ────────────────────────────────────────

const { policies } = loadPoliciesFromDir({
  dir: path.join(__dirname, "policies"),
})

const authz = createAuthz({ policies })

// ── Suite 1: canonical examples ───────────────────────────────────────────────

const { passed: p1, failed: f1 } = runSuite("Policy Engine — Canonical Examples", CASES, authz)

// ── Suite 2: match DSL examples ───────────────────────────────────────────────

const authzDsl = createAuthz({ policies: MATCH_DSL_POLICIES })
const { passed: p2, failed: f2 } = runSuite("Match DSL — Declarative Examples", MATCH_DSL_CASES, authzDsl)

// ── Suite 3: escape hatches (task 7) ─────────────────────────────────────────

console.log("\n=== Escape Hatches — customCondition + replacePolicies ===\n")

let p3 = 0
let f3 = 0

// 3a) customCondition: load extras.json with a real business-hours function
const isBusinessHours = (): boolean => {
  const hour = new Date().getHours()
  return hour >= 9 && hour < 18
}

const { policies: policiesWithExtras } = loadPoliciesFromDir({
  dir: path.join(__dirname, "extras"),
  customConditions: {
    "business-hours": (_input) => isBusinessHours(),
  },
})

const authzWithExtras = createAuthz({ policies: policiesWithExtras })

// The business-hours policy grants lead.read only during working hours.
// We do not assert an expectedAllowed here because the outcome depends on the clock.
const bhDecision = authzWithExtras.evaluate({
  principal: PRINCIPALS.ana_seller_c1,
  action: "lead.read",
  resource: RESOURCES.pool_lead_c1,
})
const bhHour = new Date().getHours()
const bhInHours = bhHour >= 9 && bhHour < 18
const bhIcon = bhDecision.allowed === bhInHours ? "✓" : "✗"
if (bhDecision.allowed === bhInHours) p3++; else f3++
console.log(`${bhIcon} [${bhDecision.allowed ? "ALLOW" : "DENY"}] customCondition: business-hours guard (clock=${bhHour}h, inHours=${bhInHours})`)
if (bhDecision.auditedPolicyIds.length > 0) {
  console.log(`    audited: ${bhDecision.auditedPolicyIds.join(", ")}`)
}

// 3b) extraPolicies: inject a raw TS policy alongside JSON ones
import type { Policy } from "../engine/types"
const superAdminPolicy: Policy = {
  id: "extra-super-admin",
  description: "Injected TS policy — super-admin reads everything",
  effect: "allow",
  principals: ["group:super-admins"],
  actions: ["*"],
  resources: ["*"],
}

const { policies: policiesWithExtra } = loadPoliciesFromDir({
  dir: path.join(__dirname, "extras"),
  customConditions: { "business-hours": () => true },
  extraPolicies: [superAdminPolicy],
})

const authzExtra = createAuthz({ policies: policiesWithExtra })
const superAdminPrincipal = { id: "sa1", tenantId: "t1", scopes: [], groups: ["super-admins"] }
const extraDecision = authzExtra.evaluate({
  principal: superAdminPrincipal,
  action: "lead.delete",
  resource: RESOURCES.pool_lead_c1,
})
const extraOk = extraDecision.allowed === true
if (extraOk) p3++; else f3++
console.log(`${extraOk ? "✓" : "✗"} [${extraDecision.allowed ? "ALLOW" : "DENY"}] extraPolicies: super-admin (injected TS policy) can lead.delete`)

// 3c) replacePolicies: swap the catalog at runtime — before/after
const authzReplace = createAuthz({ policies })

const beforeReplace = authzReplace.evaluate({
  principal: PRINCIPALS.ana_seller_c1,
  action: "lead.read",
  resource: RESOURCES.pool_lead_c1,
})
const beforeOk = beforeReplace.allowed === true
if (beforeOk) p3++; else f3++
console.log(`${beforeOk ? "✓" : "✗"} [${beforeReplace.allowed ? "ALLOW" : "DENY"}] replacePolicies BEFORE swap: seller reads pool lead`)

// Swap to an empty catalog — all requests become implicit_deny
authzReplace.replacePolicies([])

const afterReplace = authzReplace.evaluate({
  principal: PRINCIPALS.ana_seller_c1,
  action: "lead.read",
  resource: RESOURCES.pool_lead_c1,
})
const afterOk = afterReplace.allowed === false
if (afterOk) p3++; else f3++
console.log(`${afterOk ? "✓" : "✗"} [${afterReplace.allowed ? "ALLOW" : "DENY"}] replacePolicies AFTER swap (empty catalog): same request is now denied`)

// ── Suite 4: middleware stub harness (task 9) ─────────────────────────────────

console.log("\n=== Middleware — attachContext + authorize stub harness ===\n")

let p4 = 0
let f4 = 0

// Stub request/response factory
function makeReq(principal = PRINCIPALS.ana_seller_c1): RequestLike {
  return { authz: { principal, context: {}, filtered: {} } }
}

function makeRes(): ResponseLike & { _status?: number; _body?: unknown } {
  const r: ResponseLike & { _status?: number; _body?: unknown } = {
    _status: 200,
    _body: null,
    status(code: number) { r._status = code; return r },
    json(body: unknown) { r._body = body },
  }
  return r
}

// Wire up attachContext
const attachContext = createAttachContext({
  extractPrincipal: (req) => (req as RequestLike & { user: typeof PRINCIPALS.ana_seller_c1 }).user,
})

// Run async middleware cases inside an IIFE (top-level await not available in CommonJS)
void (async () => {
  // 4a) enforce mode — allowed
  {
    const req = makeReq(PRINCIPALS.ana_seller_c1) as RequestLike & { user: typeof PRINCIPALS.ana_seller_c1 }
    req.user = PRINCIPALS.ana_seller_c1
    const res = makeRes()
    let nextCalled = false

    const mw = authorize(authz, [
      { action: "lead.read", resolve: async () => RESOURCES.pool_lead_c1, mode: "enforce" },
    ])

    attachContext(req, res, () => {})
    await mw(req, res, () => { nextCalled = true })

    const ok = nextCalled && res._status === 200
    if (ok) p4++; else f4++
    console.log(`${ok ? "✓" : "✗"} enforce: seller reads pool lead → next() called (${res._status})`)
  }

  // 4b) enforce mode — denied → 403
  {
    const req = makeReq(PRINCIPALS.ana_seller_c1)
    const res = makeRes()
    let nextCalled = false

    const mw = authorize(authz, [
      { action: "lead.read", resolve: async () => RESOURCES.bruno_lead_c1, mode: "enforce" },
    ])

    await mw(req, res, () => { nextCalled = true })

    const ok = !nextCalled && res._status === 403
    if (ok) p4++; else f4++
    const body = res._body as { error: string; failures?: { action: string }[] } | null
    console.log(`${ok ? "✓" : "✗"} enforce: seller reads Bruno's lead → 403 forbidden (failures: ${body?.failures?.length ?? 0})`)
  }

  // 4c) filter mode — splits allowed vs denied leads
  {
    const req = makeReq(PRINCIPALS.ana_seller_c1)
    const res = makeRes()
    let nextCalled = false

    const mw = authorize(authz, [
      {
        action: "lead.read",
        resolve: async () => [RESOURCES.ana_lead_c1, RESOURCES.bruno_lead_c1],
        mode: "filter",
      },
    ])

    await mw(req, res, () => { nextCalled = true })

    const filtered = req.authz?.filtered?.["lead.read"] ?? []
    const ok = nextCalled && res._status === 200 && filtered.length === 1 && filtered[0].id === RESOURCES.ana_lead_c1.id
    if (ok) p4++; else f4++
    console.log(`${ok ? "✓" : "✗"} filter: from [ana_lead, bruno_lead] → filtered to ${filtered.length} allowed lead(s)`)
  }

  // 4d) 401 — no principal
  {
    const req: RequestLike = {}
    const res = makeRes()
    let nextCalled = false

    const mw = authorize(authz, [
      { action: "lead.read", resolve: async () => RESOURCES.pool_lead_c1 },
    ])

    await mw(req, res, () => { nextCalled = true })

    const ok = !nextCalled && res._status === 401
    if (ok) p4++; else f4++
    const body = res._body as { error: string } | null
    console.log(`${ok ? "✓" : "✗"} 401: no principal → ${body?.error ?? "?"} (${res._status})`)
  }

  // ── Summary ─────────────────────────────────────────────────────────────────

  const totalPassed = p1 + p2 + p3 + p4
  const totalFailed = f1 + f2 + f3 + f4

  console.log(`\n${totalPassed} passed, ${totalFailed} failed\n`)

  if (totalFailed > 0) process.exit(1)
})()
