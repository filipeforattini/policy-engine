# policy-engine

**Declarative, wildcard-friendly authorization engine with allow/deny/audit effects and tenant isolation out of the box.**

---

## Why this exists

This repository is a high-fidelity reference design — not a production library. Read it to understand the model, copy the patterns, and adapt the ideas. The goal is to show how a clean policy engine lets developers *abstract the world through policies* without writing custom authorization logic for every endpoint.

---

## Mental model in 1 minute

```
Principal × Action × Resource × Context  →  Decision
```

The engine evaluates an `(input)` tuple against a catalog of policies and returns a `Decision`.

**Evaluation precedence** — higher row wins:

| Priority | Reason | Condition |
|---|---|---|
| 1 | `tenant_mismatch` | principal and resource have different non-null `tenantId` |
| 2 | `explicit_deny` | at least one `deny` policy fully matched |
| 3 | `allow` | at least one `allow` policy fully matched |
| 4 | `implicit_deny` | no policy matched — default closed |

`audit` policies are orthogonal: they never affect the gate. They accumulate in `Decision.auditedPolicyIds`.

---

## Quickstart

```ts
import { createAuthz } from "./src"

const authz = createAuthz({
  policies: [
    {
      id: "leads-read-pool",
      description: "Seller reads unowned leads in their channel",
      effect: "allow",
      principals: ["scope:lead.read"],
      actions: ["lead.read"],
      resources: ["lead:*"],
      condition: ({ principal, resource }) =>
        principal.groups.includes(resource.attrs?.channelId as string) &&
        resource.attrs?.assignedTo === null,
    },
  ],
})

// ALLOW
const d1 = authz.evaluate({
  principal: { id: "s1", tenantId: "t1", scopes: ["lead.read"], groups: ["channel:c1"] },
  action: "lead.read",
  resource: { type: "lead", id: "l1", tenantId: "t1", attrs: { channelId: "channel:c1", assignedTo: null } },
})
console.log(d1.allowed, d1.reason)  // true  "allow"

// IMPLICIT DENY
const d2 = authz.evaluate({
  principal: { id: "s1", tenantId: "t1", scopes: ["lead.read"], groups: ["channel:c1"] },
  action: "lead.read",
  resource: { type: "lead", id: "l2", tenantId: "t1", attrs: { channelId: "channel:c1", assignedTo: "s2" } },
})
console.log(d2.allowed, d2.reason)  // false  "implicit_deny"
console.log(d2.candidatePolicies)   // [{ id: "leads-read-pool", missing: ["condition did not match"] }]
```

---

## Data model

### Principal

| Field | Type | Description |
|---|---|---|
| `id` | `string` | Unique user identifier |
| `tenantId` | `string \| null` | Tenant scope; `null` = platform principal (crosses all tenants) |
| `scopes` | `string[]` | Permission tokens (e.g. `lead.read`, `lead.**`) |
| `groups` | `string[]` | Membership tokens (e.g. `channel:c1`, `admins`) |
| `attrs` | `Record<string, unknown>` | Arbitrary attributes (e.g. `{ role: "manager" }`) |

> **No `roles` field.** Roles are redundant with `groups` and add cognitive load. Use `groups` for membership and `scopes` for capabilities.

### Resource

| Field | Type | Description |
|---|---|---|
| `type` | `string` | Dot-namespaced resource type (e.g. `lead`, `lead.draft`) |
| `id` | `string` | Resource identifier |
| `tenantId` | `string \| null` | Tenant scope; `null` = global resource (accessible by all tenants) |
| `attrs` | `Record<string, unknown>` | Runtime attributes used in `match` conditions |

### Policy

| Field | Type | Description |
|---|---|---|
| `id` | `string` | Unique identifier |
| `description` | `string` | Human-readable intent |
| `effect` | `"allow" \| "deny" \| "audit"` | Gate behavior |
| `principals` | `string[]` | Glob patterns matched against the compiled principal set |
| `actions` | `string[]` | Glob patterns matched against the action |
| `resources` | `string[]` | Glob patterns matched against `type:id` or `type` |
| `match` | `MatchNode` | Declarative condition (compiled at load time) |
| `condition` | `(input) => boolean` | TypeScript condition function (inline policies only) |

The **compiled principal set** for a principal `p` is:
```
[p.id, "user:{p.id}", "scope:{s}" for each scope, "group:{g}" for each group, "*"]
```

---

## Wildcards

Wildcards are supported in `principals`, `actions`, and `resources` patterns. They are **identity patterns** — only valid on the left-hand side of a match, never in `match` DSL values.

| Token | Meaning | Matches | Does NOT match |
|---|---|---|---|
| `*` | Any single segment (no dot crossing) | `lead.read` vs `*.read` ✓ | `lead.move.funnel` vs `*.read` ✗ |
| `**` | Zero or more segments (crosses dots) | `lead.move.funnel` vs `lead.**` ✓ | — |
| `?` | Exactly one character (no dot) | `lead:l1` vs `lead:l?` ✓ | `lead:l12` vs `lead:l?` ✗ |
| `{a,b}` | Alternation | `scope:lead.read` vs `scope:lead.{read,claim}` ✓ | `scope:lead.move` vs `scope:lead.{read,claim}` ✗ |
| `[abc]` | Character class | `lead:l1` vs `lead:l[12]` ✓ | `lead:l3` vs `lead:l[12]` ✗ |

**Bidirectionality:** a principal carrying a broader scope satisfies a narrower policy pattern. A principal with `scope:lead.**` satisfies a policy requiring `scope:lead.read`.

---

## Match DSL

The `match` field replaces inline `condition` functions with a serializable, JSON-compatible expression tree. Policies with `match` can be stored in `.json` files and loaded by `loadPoliciesFromDir`.

### Literal equality

```ts
match: { "resource.status": "novo" }
// resource.attrs.status === "novo"
```

### `@ref` — compare against another path

```ts
match: {
  "resource.channelId": "@principal.groups",  // string vs array → includes check
  "resource.assignedTo": "@principal.id",     // string vs string → equality
}
```

### `null` — strict null check

```ts
match: { "resource.assignedTo": null }
// resource.attrs.assignedTo === null
```

### `*` — wildcard (always passes, documents intent)

```ts
match: { "resource.type": "*" }
```

### Operator object-form

```ts
match: {
  "resource.status": { in: ["novo", "contatado"] },
  "resource.amount": { "<": 10000 },
  "resource.email":  { regex: "^.+@stone\\.com\\.br$" },
  "resource.id":     { startsWith: "lead-" },
  "resource.tag":    { exists: true },
}
```

All supported operators: `==`, `!=`, `<`, `<=`, `>`, `>=`, `in`, `notIn`, `regex`, `startsWith`, `endsWith`, `contains`, `exists`.

### Boolean composition — `anyOf` / `allOf` / `not`

```ts
// Three separate policies collapsed into one
match: {
  anyOf: [
    { "resource.channelId": "@principal.groups", "resource.assignedTo": null },          // pool lead
    { "resource.channelId": "@principal.groups", "resource.assignedTo": "@principal.id" }, // own lead
    { "resource.channelId": "@principal.groups", "resource.sharedWith": "@principal.id" }, // shared with me
  ],
}
```

### `customCondition` — escape hatch for complex TS logic

JSON policy:
```json
{
  "id": "leads-read-business-hours-only",
  "effect": "allow",
  "principals": ["scope:lead.read"],
  "actions": ["lead.read"],
  "resources": ["lead:*"],
  "customCondition": "business-hours"
}
```

Loader call:
```ts
loadPoliciesFromDir({
  dir: "policies/",
  customConditions: {
    "business-hours": () => new Date().getHours() >= 9 && new Date().getHours() < 18,
  },
})
```

If `"business-hours"` is not in the map, the loader throws at startup — not silently at eval time.

---

## Tenant isolation

Tenant isolation is enforced **at the engine level**, before any policy is evaluated. It cannot be bypassed by a policy.

```
principal.tenantId  ──┐
                       ├── both non-null AND different → DENY (tenant_mismatch)
resource.tenantId   ──┘

principal.tenantId == null  →  platform principal — crosses all tenants
resource.tenantId  == null  →  global resource — accessible by any tenant
```

**Example — platform admin** (tenantId: null) reads a tenant-scoped lead:

```ts
principal: { id: "platform-admin", tenantId: null, scopes: ["lead.**"], groups: [] }
resource:  { type: "lead", id: "l1", tenantId: "t1", ... }
// tenant guard: null vs "t1" → null side bypasses → proceed to policy evaluation
```

**Example — global resource** (settings, policy catalog):
```ts
resource: { type: "settings", id: "global", tenantId: null, ... }
// any principal can pass the tenant guard; access still requires a matching policy
```

Why this belongs in the engine and not in a policy: a `deny` policy can be bypassed by a narrower `allow`; tenant isolation must be unconditional.

---

## Effects

| Effect | Affects `allowed`? | Use case |
|---|---|---|
| `allow` | Yes — sets `allowed: true` | Grant access |
| `deny` | Yes — overrides allow, sets `allowed: false` | Explicit block (e.g. restricted resources) |
| `audit` | **No** — never gates | Shadow rollout, observability, compliance logging |

**Shadow rollout workflow:**
1. Deploy a new restrictive rule as `effect: "audit"`.
2. Run for one week. Observe `auditedPolicyIds` in logs/telemetry — no access is blocked.
3. Verify the population is as expected (no false positives).
4. Flip to `effect: "deny"`. Zero surprises.

```ts
const decision = authz.evaluate(input)

// Allow/deny is unaffected by audit policies
console.log(decision.allowed)           // true or false

// Which audit policies matched (for logging/telemetry)
console.log(decision.auditedPolicyIds)  // ["audit-lead-reads-by-seller"]
```

---

## Middleware with route examples

### (a) Attach principal context

```ts
import express from "express"
import { createAttachContext } from "./src"

const app = express()

app.use(createAttachContext({
  extractPrincipal: (req) => {
    // decode your JWT here — no JWT lib included in this engine
    const payload = verifyJwt(req.headers.authorization!)
    return {
      id: payload.sub,
      tenantId: payload.tenantId ?? null,
      scopes: payload.scopes ?? [],
      groups: payload.groups ?? [],
      attrs: payload.attrs,
    }
  },
  extractContext: (req) => ({ ip: req.socket?.remoteAddress }),
}))
```

### (b) `authorize` — enforce mode (all resources must pass)

```ts
import { authorize } from "./src"

router.get("/leads/:id", authorize(authz, [
  {
    action: "lead.read",
    resolve: async (req) => await db.leads.findById(req.params.id),
    mode: "enforce",  // default
  },
]), handler)

// On failure → 403:
// {
//   "error": "forbidden",
//   "principal": { "id": "s1", "tenantId": "t1", "scopes": [...], "groups": [...] },
//   "failures": [{ "action": "lead.read", "resource": {...}, "reason": "implicit_deny", "candidatePolicies": [...] }]
// }
```

### (c) Factory form — checks resolved at request time

```ts
router.post("/leads/:id/move", authorize(authz, async (req) => {
  const lead = await db.leads.findById(req.params.id)
  return [
    { action: "lead.read",  resolve: async () => lead },
    { action: "lead.move",  resolve: async () => lead },
  ]
}), handler)
```

### (d) `filter` mode — list endpoints

```ts
router.get("/leads", authorize(authz, [
  {
    action: "lead.read",
    resolve: async (req) => await db.leads.findAll({ channelId: req.query.channelId }),
    mode: "filter",  // no 403 — shrinks the list
  },
]), (req, res) => {
  // Only the allowed leads are here
  const leads = req.authz!.filtered["lead.read"]
  res.json(leads)
})
```

---

## Loader

### Directory layout

```
policies/
  leads.json
  channels.json
  sellers.json
  control.json
```

Each file is a **JSON array** of `JsonPolicy` objects. Files are loaded in alphabetical order; policies within each file in source order.

### Load and validate

```ts
import { loadPoliciesFromDir, createAuthz } from "./src"

const { policies, json } = loadPoliciesFromDir({
  dir: "policies/",
})

const authz = createAuthz({ policies })
```

Validation runs at load time. A typo like `"effect": "permit"` produces:

```
leads[2] (id: "my-policy"): "effect" must be one of allow/deny/audit, got "permit"
```

### Hot reload with `replacePolicies`

```ts
// Reload without restarting the process
const { policies: fresh } = loadPoliciesFromDir({ dir: "policies/" })
authz.replacePolicies(fresh)
// All subsequent evaluate() calls use the new catalog immediately
```

### JSON Schema

`src/loader/schema.json` is a JSON Schema Draft-07 document covering the full `JsonPolicy` shape including all `match` operator forms. Wire it in your editor for autocomplete and inline validation.

```json
// .vscode/settings.json
{
  "json.schemas": [
    { "fileMatch": ["policies/*.json"], "url": "./src/loader/schema.json" }
  ]
}
```

---

## Decision shape + explain-deny

### Allow

```json
{
  "allowed": true,
  "reason": "allow",
  "matchedPolicyIds": ["leads-read-mine-by-seller"],
  "auditedPolicyIds": ["audit-lead-reads-by-seller"],
  "candidatePolicies": []
}
```

### Explicit deny

```json
{
  "allowed": false,
  "reason": "explicit_deny",
  "matchedPolicyIds": ["match-restricted-deny"],
  "auditedPolicyIds": [],
  "candidatePolicies": []
}
```

### Implicit deny with explain-deny

```json
{
  "allowed": false,
  "reason": "implicit_deny",
  "matchedPolicyIds": [],
  "auditedPolicyIds": ["audit-lead-reads-by-seller"],
  "candidatePolicies": [
    {
      "id": "leads-read-mine-by-seller",
      "description": "Seller reads a lead assigned to them in their own channel",
      "effect": "allow",
      "requiredPrincipals": ["scope:lead.read"],
      "missing": ["condition did not match"]
    },
    {
      "id": "leads-read-by-admin",
      "description": "Admin reads any lead without restrictions",
      "effect": "allow",
      "requiredPrincipals": ["group:admins"],
      "missing": ["principal — need one of: group:admins"]
    }
  ]
}
```

`candidatePolicies` lists every policy that matched on action + resource but failed on principal or condition. In production this is the 403 body — instead of returning a generic "forbidden", your API tells the caller exactly which policies exist, which one was closest, and what it was missing. Debugging a 403 becomes inspection, not guesswork.

---

## Appendix A — Decision log

Major design choices made during the design session:

- **No `roles` field** — redundant with `groups`; reduces cognitive load when writing policies. Use `group:admins` instead of `role:admin`.
- **`tenantId: string | null` on both sides** — first-class field, not an attr. `null` has explicit semantics (platform principal / global resource). Tenant isolation runs before any policy.
- **Scopes and groups unified in one principal set** — `scope:lead.read`, `group:admins`, `user:s1`, and `*` are all just patterns. The engine compiles them into a flat array and runs one `matchAny` pass.
- **Actions are dot-namespaced** — same namespace as scopes (`lead.read`, `lead.move.funnel`). A principal with `scope:lead.**` satisfies any action in the lead namespace.
- **Globstar bidirectionality** — a principal carrying a broader scope (`scope:lead.**`) satisfies a narrower policy pattern (`scope:lead.read`). Enables platform principals to carry wildcard scopes.
- **Match DSL is Mongo-style** — `{ "resource.assignedTo": "@principal.id" }` reads like a query, not a predicate function. Serializable to JSON, survives process restarts, editable without a TypeScript compiler.
- **`@ref` for cross-field comparisons** — avoids hardcoded string values when comparing two dynamic fields. `"@principal.groups"` resolves at eval time.
- **`anyOf` collapses policy explosion** — without it, "pool lead OR assigned lead OR shared lead" requires 3 separate policies with identical action/resource patterns. With `anyOf`, it is one policy.
- **`audit` is orthogonal to allow/deny** — it never changes the gate. This is the shadow rollout primitive. Ship as audit, observe, then promote to deny.
- **`candidatePolicies` in implicit_deny** — explain-deny without a dedicated explain endpoint. The same `evaluate` call that returns `allowed: false` also tells you why, without a second round-trip.
- **`customConditions` fail at load time** — an unresolved `customCondition` name throws when loading policies, not silently at the first eval that hits the policy.
- **No file watcher** — the engine provides `replacePolicies()`; wiring it to inotify or a config endpoint is the caller's responsibility.
- **No YAML/JSON5** — standard JSON only; editors and CI have first-class JSON Schema support.

---

## Appendix B — What this is NOT

- **Not a production library.** No versioning, no semver, no support contract. Fork and own it.
- **Not Express-specific.** The middleware uses duck-typed `req`/`res`/`next` — wire it to Fastify, Koa, or a raw `http.Server`.
- **Not Cedar, Rego, or XACML.** No policy language parser, no rule graph, no external evaluation engine.
- **Not a parent-graph / hierarchy engine.** There is no resource tree (`org → channel → lead`). Model hierarchy through `attrs` and match conditions.
- **Not an obligation engine.** Policies say allow/deny/audit. They do not trigger side effects or return data transformations.
- **Not a policy priority engine.** The only precedence rule is `deny > allow`. There is no numeric priority or ordering between policies of the same effect.
- **Not a file watcher.** `loadPoliciesFromDir` reads once; hot reload is your responsibility.
- **Not YAML or JSON5.** Standard JSON only. YAML is a trap.
