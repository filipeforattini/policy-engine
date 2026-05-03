# policy-engine

**A declarative, wildcard-friendly authorization engine. Write policies — not code.**

Define who can do what to which resource under which conditions. Ship as `audit` to observe, flip to `deny` to enforce. Tenant isolation, match DSL, glob wildcards, and explain-deny built in.

> **Reference design.** Not a production library. Fork it, own it, adapt it.

---

## Table of contents

1. [How it works](#1-how-it-works)
2. [Quickstart](#2-quickstart)
3. [Data model](#3-data-model)
4. [Principals and the compiled principal set](#4-principals-and-the-compiled-principal-set)
5. [Wildcards](#5-wildcards)
6. [Effects — allow / deny / audit](#6-effects--allow--deny--audit)
7. [Match DSL](#7-match-dsl)
8. [Tenant isolation](#8-tenant-isolation)
9. [JSON policies and the loader](#9-json-policies-and-the-loader)
10. [Escape hatches](#10-escape-hatches)
11. [Middleware](#11-middleware)
12. [Decision shape and explain-deny](#12-decision-shape-and-explain-deny)
13. [Access-control patterns — RBAC and ABAC](#13-access-control-patterns--rbac-and-abac)
14. [Design decisions](#14-design-decisions)
15. [Non-goals](#15-non-goals)

---

## 1. How it works

```
Principal  ──────────────────────────────────────────────────────┐
                                                                  ▼
Action     ──────────────────────────────────────────────────► evaluate(input, policies)  ──►  Decision
                                                                  ▲
Resource   ──────────────────────────────────────────────────────┘
Context    ──────────────────────────────────────────────────────┘
```

The engine iterates every policy, classifies it as `allow`, `deny`, `audit`, or `candidate` (partial match), and returns a `Decision` according to this precedence:

| Priority | reason | When |
|---|---|---|
| 1 | `tenant_mismatch` | principal and resource have different non-null `tenantId` |
| 2 | `explicit_deny` | one or more `deny` policies fully matched |
| 3 | `allow` | one or more `allow` policies fully matched |
| 4 | `implicit_deny` | nothing matched — default closed |

`audit` policies never change the gate. They accumulate separately in `auditedPolicyIds`.

---

## 2. Quickstart

```bash
npm install
npm run examples   # runs src/examples/run.ts — the living spec
```

```ts
import { createAuthz } from "./src"

const authz = createAuthz({
  policies: [
    {
      id: "leads-read-own",
      description: "Seller reads their own lead",
      effect: "allow",
      principals: ["scope:lead.read"],
      actions: ["lead.read"],
      resources: ["lead:*"],
      condition: ({ principal, resource }) =>
        resource.attrs?.assignedTo === principal.id,
    },
    {
      id: "leads-read-deny-archived",
      description: "Nobody reads archived leads",
      effect: "deny",
      principals: ["*"],
      actions: ["lead.read"],
      resources: ["lead:*"],
      condition: ({ resource }) => resource.attrs?.status === "archived",
    },
  ],
})

// ✓  ALLOW — own lead
authz.evaluate({
  principal: { id: "s1", tenantId: "t1", scopes: ["lead.read"], groups: [] },
  action: "lead.read",
  resource: { type: "lead", id: "l1", tenantId: "t1", attrs: { assignedTo: "s1", status: "active" } },
})
// { allowed: true, reason: "allow", matchedPolicyIds: ["leads-read-own"], ... }

// ✗  EXPLICIT DENY — archived overrides allow
authz.evaluate({
  principal: { id: "s1", tenantId: "t1", scopes: ["lead.read"], groups: [] },
  action: "lead.read",
  resource: { type: "lead", id: "l2", tenantId: "t1", attrs: { assignedTo: "s1", status: "archived" } },
})
// { allowed: false, reason: "explicit_deny", matchedPolicyIds: ["leads-read-deny-archived"], ... }

// ✗  IMPLICIT DENY — no matching policy
authz.evaluate({
  principal: { id: "s1", tenantId: "t1", scopes: ["lead.read"], groups: [] },
  action: "lead.delete",
  resource: { type: "lead", id: "l1", tenantId: "t1", attrs: {} },
})
// { allowed: false, reason: "implicit_deny", candidatePolicies: [...] }
```

---

## 3. Data model

### Principal

```ts
type Principal = {
  id: string                        // unique user identifier
  tenantId: string | null           // null = platform principal (crosses all tenants)
  scopes: string[]                  // capability tokens, e.g. ["lead.read", "lead.move"]
  groups: string[]                  // membership tokens, e.g. ["channel:c1", "admins"]
  attrs?: Record<string, unknown>   // arbitrary, e.g. { role: "manager" }
}
```

> **No `roles` field.** Use `groups` for membership and `scopes` for capabilities. Roles are just named groups — they add a layer without adding power.

### Resource

```ts
type Resource = {
  type: string                      // dot-namespaced type, e.g. "lead", "lead.draft"
  id: string                        // resource identifier
  tenantId: string | null           // null = global resource (any tenant may access)
  attrs?: Record<string, unknown>   // runtime data used in match conditions
}
```

### Policy

```ts
type Policy = {
  id: string
  description: string
  effect: "allow" | "deny" | "audit"
  principals: string[]              // glob patterns — see §5
  actions: string[]                 // glob patterns — see §5
  resources: string[]               // glob patterns — see §5
  condition?: (input: AuthzInput) => boolean   // TypeScript function (inline policies)
  match?: MatchNode                 // declarative DSL (JSON policies) — see §7
}
```

A policy matches when **all three** pattern arrays match **and** the `condition`/`match` passes.

---

## 4. Principals and the compiled principal set

Before pattern matching, the engine expands a `Principal` into a **flat string set**:

```
principal = { id: "s1", scopes: ["lead.read"], groups: ["channel:c1", "admins"] }

compiled set = [
  "s1",                  ← bare id
  "user:s1",             ← prefixed id
  "scope:lead.read",     ← each scope prefixed
  "group:channel:c1",    ← each group prefixed
  "group:admins",
  "*",                   ← wildcard — always present
]
```

A policy's `principals` array is matched against this set using `matchAny`. A policy that lists `["group:admins"]` allows any principal whose groups include `"admins"`.

**Bidirectionality:** a principal carrying a broader scope satisfies a narrower policy pattern:

```
principal scope:  lead.**
policy principal: scope:lead.read   ← lead.** covers lead.read ✓
```

This lets platform principals carry wildcard scopes and still match fine-grained policies.

---

## 5. Wildcards

Wildcards are valid in `principals`, `actions`, and `resources` patterns. They operate on dot-namespaced segments and colon-separated `type:id` pairs.

| Token | Meaning | Example pattern | Matches | Does NOT match |
|---|---|---|---|---|
| `*` | Any single segment — no dot crossing | `*.read` | `lead.read` | `lead.move.funnel` |
| `**` | Zero or more segments — crosses dots | `lead.**` | `lead.read`, `lead.move.funnel` | `channel.read` |
| `?` | Exactly one character — no dot crossing | `lead:l?` | `lead:l1`, `lead:la` | `lead:l12` |
| `{a,b}` | Alternation — expands to `(a\|b)` | `scope:lead.{read,claim}` | `scope:lead.read`, `scope:lead.claim` | `scope:lead.move` |
| `[abc]` | Character class | `lead:l[12]` | `lead:l1`, `lead:l2` | `lead:l3` |

### `*` — single segment

```ts
// Allow any *.read action (e.g. lead.read, channel.read, seller.read)
{ actions: ["*.read"] }

// Allow on any resource type (but not nested types like lead.draft)
{ resources: ["*:*"] }
```

### `**` — globstar (crosses dots)

```ts
// Allow everything in the lead namespace: lead.read, lead.move, lead.move.funnel, ...
{ actions: ["lead.**"] }

// Allow any action at all
{ actions: ["**"] }
```

### `?` — single character

```ts
// Match lead:l1, lead:l2, lead:la — id is exactly 2 chars
{ resources: ["lead:l?"] }

// Match lead:l12 requires two ? wildcards
{ resources: ["lead:l??"] }
```

### `{a,b}` — alternation

```ts
// Match scope:lead.read OR scope:lead.claim
{ principals: ["scope:lead.{read,claim}"] }

// Match lead.create OR lead.update
{ actions: ["lead.{create,update}"] }
```

### `[abc]` — character class

```ts
// Match lead:l1 or lead:l2, but NOT lead:l3
{ resources: ["lead:l[12]"] }

// Match lead:la, lead:lb, lead:lc
{ resources: ["lead:l[a-c]"] }
```

### Combining wildcards

```ts
// Seller reads any pool lead (unowned) in a channel they belong to
{
  principals: ["scope:lead.{read,claim}"],
  actions: ["lead.read"],
  resources: ["lead:*"],
}

// Admin performs any nested action on any lead
{
  principals: ["group:admins"],
  actions: ["lead.**"],
  resources: ["lead:*"],
}
```

---

## 6. Effects — allow / deny / audit

### `allow`

Grants access when the policy fully matches. Multiple allow policies: first match wins (all are recorded in `matchedPolicyIds`).

```ts
{
  id: "leads-read-pool",
  effect: "allow",
  principals: ["scope:lead.read"],
  actions: ["lead.read"],
  resources: ["lead:*"],
  condition: ({ principal, resource }) =>
    principal.groups.includes(resource.attrs?.channelId as string) &&
    resource.attrs?.assignedTo === null,
}
```

### `deny`

Explicitly blocks access. `deny` always wins over `allow` — order does not matter.

```ts
// Block everyone from reading archived leads, even admins
{
  id: "leads-deny-archived",
  effect: "deny",
  principals: ["*"],
  actions: ["lead.read"],
  resources: ["lead:*"],
  condition: ({ resource }) => resource.attrs?.status === "archived",
}

// Block a specific user (emergency revocation)
{
  id: "deny-suspended-user",
  effect: "deny",
  principals: ["user:s99"],
  actions: ["**"],
  resources: ["*"],
}

// Block all writes outside business hours (pairs with customCondition)
{
  id: "deny-writes-off-hours",
  effect: "deny",
  principals: ["*"],
  actions: ["lead.create", "lead.update", "lead.delete"],
  resources: ["lead:*"],
  condition: () => {
    const hour = new Date().getHours()
    return hour < 9 || hour >= 18
  },
}
```

### `audit`

Matches like any other policy but **never changes `allowed`**. Matched policy ids accumulate in `Decision.auditedPolicyIds`. Use it for shadow testing a rule before enforcing it.

```ts
// Shadow-test a new restrictive rule for one week
{
  id: "audit-lead-reads-by-seller",
  effect: "audit",
  principals: ["scope:lead.read"],
  actions: ["lead.read"],
  resources: ["lead:*"],
}
```

```ts
const decision = authz.evaluate(input)

// Gate is unaffected
console.log(decision.allowed)           // true (allow from another policy)

// But we can see which audit policies matched
console.log(decision.auditedPolicyIds)  // ["audit-lead-reads-by-seller"]
```

**Shadow rollout workflow:**
1. Deploy as `effect: "audit"` — observe `auditedPolicyIds` in logs for a week.
2. Confirm the population is exactly what you expect (no false positives).
3. Change `effect` to `"deny"` — no surprises on day one.

### Precedence in practice

```ts
// Three policies in the catalog:
//   allow:   group:admins  reads  lead:*    (no condition)
//   deny:    *             reads  lead:*    (if resource.restricted === true)
//   audit:   scope:lead.read reads lead:*  (always)

// Admin reads a normal lead → ALLOW
// auditedPolicyIds: ["audit-lead-reads-by-seller"] (audit fired too)
authz.evaluate({ principal: admin, action: "lead.read", resource: normalLead })

// Admin reads a restricted lead → EXPLICIT DENY (deny beats allow)
authz.evaluate({ principal: admin, action: "lead.read", resource: restrictedLead })

// Seller without scope reads a lead → IMPLICIT DENY
// candidatePolicies shows which policies almost matched
authz.evaluate({ principal: noScopeSeller, action: "lead.read", resource: normalLead })
```

---

## 7. Match DSL

The `match` field is a serializable, JSON-compatible condition tree that replaces the `condition` function. Policies with `match` can live in `.json` files and be loaded without a TypeScript compiler.

All paths are dot-namespaced and resolved at eval time:

| Path prefix | Resolves to |
|---|---|
| `principal.id` | `input.principal.id` |
| `principal.tenantId` | `input.principal.tenantId` |
| `principal.scopes` | `input.principal.scopes` (array) |
| `principal.groups` | `input.principal.groups` (array) |
| `principal.attrs.<key>` | `input.principal.attrs?.[key]` |
| `resource.id` | `input.resource.id` |
| `resource.type` | `input.resource.type` |
| `resource.tenantId` | `input.resource.tenantId` |
| `resource.<key>` | `input.resource.attrs?.[key]` (shorthand) |
| `resource.attrs.<key>` | `input.resource.attrs?.[key]` (explicit) |
| `context.<key>` | `input.context?.[key]` |

### Literal equality

```ts
// resource.attrs.status === "active"
match: { "resource.status": "active" }

// principal.attrs.role === "manager"
match: { "principal.attrs.role": "manager" }

// Multiple conditions — all must pass (implicit allOf)
match: {
  "resource.status": "active",
  "principal.attrs.role": "manager",
}
```

### `null` — strict null check

```ts
// resource.attrs.assignedTo === null  (unowned pool lead)
match: { "resource.assignedTo": null }
```

### `*` — wildcard (always passes, documents intent)

```ts
match: { "resource.type": "*" }   // any type — used for self-documentation
```

### `@ref` — compare against another resolved path

```ts
// resource.assignedTo === principal.id
match: { "resource.assignedTo": "@principal.id" }

// resource.channelId is included in principal.groups (string vs array → includes check)
match: { "resource.channelId": "@principal.groups" }

// Both sides arrays: any element of principal.scopes is in resource.allowedScopes
match: { "principal.scopes": "@resource.allowedScopes" }
```

### `!` prefix — negate any value

```ts
// resource.status !== "archived"
match: { "resource.status": "!archived" }

// resource.assignedTo !== principal.id
match: { "resource.assignedTo": "!@principal.id" }
```

### Operator object-form

Use an operator object when you need richer comparisons than equality.

#### Equality operators

```ts
// == and != (same as literal and ! prefix, but explicit)
match: { "resource.status": { "==": "active" } }
match: { "resource.status": { "!=": "archived" } }

// != with @ref
match: { "resource.assignedTo": { "!=": "@principal.id" } }
```

#### Numeric / lexicographic comparisons

```ts
match: { "resource.amount":    { "<":  10000  } }
match: { "resource.score":     { "<=": 99     } }
match: { "resource.priority":  { ">":  3      } }
match: { "resource.rank":      { ">=": 1      } }

// Range: amount between 100 and 9999 (use allOf)
match: {
  allOf: [
    { "resource.amount": { ">=": 100  } },
    { "resource.amount": { "<":  9999 } },
  ]
}
```

#### `in` / `notIn`

```ts
// Status must be one of the listed values
match: { "resource.status": { in: ["active", "pending", "review"] } }

// Status must NOT be one of these
match: { "resource.status": { notIn: ["archived", "deleted"] } }

// in with @ref — resolve an array from the input at eval time
match: { "resource.channelId": { in: "@principal.groups" } }
```

#### `regex`

```ts
// Email must be a corporate address
match: { "resource.email": { regex: "^.+@acme\\.com$" } }

// ID must start with "lead-" followed by digits
match: { "resource.id": { regex: "^lead-\\d+$" } }
```

#### `startsWith` / `endsWith` / `contains`

```ts
match: { "resource.id":    { startsWith: "lead-" } }
match: { "resource.slug":  { endsWith:   "-draft" } }
match: { "resource.tags":  { contains:   "vip"    } }
```

#### `exists`

```ts
// resource.attrs.assignedTo is present (not undefined) — even if null
match: { "resource.assignedTo": { exists: true  } }

// resource.attrs.deletedAt is absent
match: { "resource.deletedAt":  { exists: false } }
```

### Boolean composition — `anyOf` / `allOf` / `not`

#### `anyOf` — OR

```ts
// Read is allowed if: pool lead, or own lead, or explicitly shared
match: {
  anyOf: [
    {
      "resource.channelId": "@principal.groups",
      "resource.assignedTo": null,            // pool
    },
    {
      "resource.channelId": "@principal.groups",
      "resource.assignedTo": "@principal.id", // own
    },
    {
      "resource.channelId": "@principal.groups",
      "resource.sharedWith": "@principal.id", // shared
    },
  ]
}
```

#### `allOf` — AND (explicit; same as root-level)

```ts
// Must be in the right channel AND the lead must be claimable
match: {
  allOf: [
    { "resource.channelId": "@principal.groups" },
    { "resource.status":    "active"            },
    { "resource.assignedTo": null               },
  ]
}
```

#### `not` — negate a sub-match

```ts
// Principal must NOT be the resource owner (e.g. for peer-review policies)
match: {
  not: { "resource.assignedTo": "@principal.id" }
}

// Must be in channel AND lead is not restricted
match: {
  allOf: [
    { "resource.channelId": "@principal.groups" },
    { not: { "resource.restricted": true } },
  ]
}
```

#### Deep nesting

```ts
// Manager reads if: (in channel AND role=manager) OR group:admins
// This is better expressed as two separate policies, but nesting works:
match: {
  anyOf: [
    {
      allOf: [
        { "resource.channelId":     "@principal.groups" },
        { "principal.attrs.role":   "manager"           },
      ]
    },
    // the second branch is better handled by a principals: ["group:admins"] policy
  ]
}
```

### Combining match with wildcards and principals

```ts
// Full policy: manager moves any lead in their channel
{
  id: "leads-move-by-manager",
  effect: "allow",
  principals: ["scope:lead.move"],          // wildcard could be scope:lead.*
  actions: ["lead.move"],
  resources: ["lead:*"],
  match: {
    "principal.attrs.role": "manager",
    "resource.channelId":   "@principal.groups",
  }
}

// Full policy: deny any write on leads created more than 90 days ago
{
  id: "deny-stale-lead-writes",
  effect: "deny",
  principals: ["*"],
  actions: ["lead.update", "lead.delete"],
  resources: ["lead:*"],
  match: { "resource.ageInDays": { ">": 90 } }
}
```

---

## 8. Tenant isolation

Tenant isolation is enforced **at engine level**, before any policy is evaluated. A policy cannot override it.

```
principal.tenantId  ──┐
                       ├──  both non-null AND different  →  DENY  (tenant_mismatch)
resource.tenantId   ──┘

principal.tenantId === null  →  platform principal, crosses all tenants
resource.tenantId  === null  →  global resource, any tenant may access
```

### Cross-tenant block

```ts
// t2 seller cannot read a t1 lead — blocked before any policy runs
authz.evaluate({
  principal: { id: "f1", tenantId: "t2", scopes: ["lead.read"], groups: [] },
  action: "lead.read",
  resource:  { type: "lead", id: "l1", tenantId: "t1", attrs: {} },
})
// { allowed: false, reason: "tenant_mismatch", matchedPolicyIds: [], candidatePolicies: [] }
```

### Platform principal (`tenantId: null`)

```ts
// Platform admin reads any lead regardless of tenant
const platformAdmin: Principal = {
  id: "platform-admin",
  tenantId: null,                           // ← bypasses tenant guard
  scopes: ["lead.**", "settings.**"],
  groups: ["admins"],
}

authz.evaluate({
  principal: platformAdmin,
  action: "lead.read",
  resource: { type: "lead", id: "l1", tenantId: "t2", attrs: {} },
})
// Tenant guard: null vs "t2" → passes
// Then evaluates against policies normally
```

### Global resource (`tenantId: null`)

```ts
// Settings catalog is global — any tenant can access it (if a policy allows)
const globalSettings: Resource = {
  type: "settings",
  id: "global",
  tenantId: null,   // ← any principal passes the tenant guard
  attrs: {},
}
```

---

## 9. JSON policies and the loader

Store policies in `.json` files. The loader validates them, compiles `match` to a function, and returns a `Policy[]` ready for `createAuthz`.

### File layout

```
policies/
  leads.json      ← [{ id, description, effect, principals, actions, resources, match? }, ...]
  channels.json
  sellers.json
  control.json
```

### A full JSON policy

```json
{
  "id": "leads-read-consolidated",
  "description": "Seller reads pool, own, or shared leads in their channel",
  "effect": "allow",
  "principals": ["scope:lead.read"],
  "actions": ["lead.read"],
  "resources": ["lead:*"],
  "match": {
    "anyOf": [
      { "resource.channelId": "@principal.groups", "resource.assignedTo": null },
      { "resource.channelId": "@principal.groups", "resource.assignedTo": "@principal.id" },
      { "resource.channelId": "@principal.groups", "resource.sharedWith": "@principal.id" }
    ]
  }
}
```

### Loading

```ts
import { loadPoliciesFromDir, createAuthz } from "./src"

const { policies, json } = loadPoliciesFromDir({ dir: "policies/" })
const authz = createAuthz({ policies })
```

### Validation

The loader validates every field at startup. A bad `effect` value produces:

```
leads[2] (id: "my-policy"): "effect" must be one of allow/deny/audit, got "permit"
```

### JSON Schema

`src/loader/schema.json` is a JSON Schema Draft-07 file covering the full `JsonPolicy` shape. Wire it in your editor:

```json
// .vscode/settings.json
{
  "json.schemas": [
    { "fileMatch": ["policies/*.json"], "url": "./src/loader/schema.json" }
  ]
}
```

### Hot reload

```ts
// Reload without restarting the process
const { policies: next } = loadPoliciesFromDir({ dir: "policies/" })
authz.replacePolicies(next)
// All subsequent evaluate() calls use the new catalog
```

---

## 10. Escape hatches

### `customCondition` — TS function referenced by name from JSON

Some conditions cannot be expressed in the `match` DSL (e.g. external API calls, clock checks, complex business logic). Reference a named function instead:

```json
{
  "id": "leads-read-business-hours",
  "description": "Lead reads are only allowed during business hours",
  "effect": "allow",
  "principals": ["scope:lead.read"],
  "actions": ["lead.read"],
  "resources": ["lead:*"],
  "customCondition": "business-hours"
}
```

```ts
const { policies } = loadPoliciesFromDir({
  dir: "policies/",
  customConditions: {
    "business-hours": () => {
      const h = new Date().getHours()
      return h >= 9 && h < 18
    },
    "caller-ip-allowlist": ({ context }) =>
      ["10.0.0.1", "10.0.0.2"].includes(context?.ip as string),
  },
})
```

If `"business-hours"` is not in the map, the loader **throws at startup** — not silently at the first evaluation.

### `extraPolicies` — inject raw TS policies alongside JSON

```ts
const { policies } = loadPoliciesFromDir({
  dir: "policies/",
  extraPolicies: [
    {
      id: "super-admin-override",
      description: "Super-admins can do anything",
      effect: "allow",
      principals: ["group:super-admins"],
      actions: ["**"],
      resources: ["*"],
    },
  ],
})
```

---

## 11. Middleware

Framework-agnostic middleware — duck-typed `req`/`res`/`next`. Works with Express, Fastify, Koa, or any `http.Server`.

### (a) Attach principal context

```ts
import express from "express"
import { createAttachContext } from "./src"

app.use(createAttachContext({
  // Extract principal from request — decode your own token here
  extractPrincipal: (req) => {
    const payload = verifyJwt(req.headers.authorization ?? "")
    return {
      id: payload.sub,
      tenantId: payload.tenantId ?? null,
      scopes: payload.scopes ?? [],
      groups: payload.groups ?? [],
      attrs: { role: payload.role },
    }
  },
  // Optional: attach request-level context (ip, requestId, etc.)
  extractContext: (req) => ({
    ip: req.socket?.remoteAddress,
    requestId: req.headers["x-request-id"],
  }),
}))
// req.authz = { principal, context, filtered: {} }
```

### (b) `enforce` mode — all resources must be allowed

```ts
import { authorize } from "./src"

// Single resource
router.get("/leads/:id",
  authorize(authz, [
    {
      action: "lead.read",
      resolve: async (req) => await db.leads.findById(req.params.id),
      mode: "enforce",  // default
    },
  ]),
  handler
)

// Multiple checks — AND logic, all must pass
router.post("/leads/:id/move",
  authorize(authz, [
    { action: "lead.read",  resolve: async (req) => await db.leads.findById(req.params.id) },
    { action: "lead.move",  resolve: async (req) => await db.leads.findById(req.params.id) },
  ]),
  handler
)
```

### (c) Factory form — checks resolved at request time

```ts
router.put("/leads/:id",
  authorize(authz, async (req) => {
    const lead = await db.leads.findById(req.params.id)
    const checks = [{ action: "lead.update", resolve: async () => lead }]
    if (lead.isShared) {
      checks.push({ action: "lead.share", resolve: async () => lead })
    }
    return checks
  }),
  handler
)
```

### (d) `any` mode — at least one resource must be allowed

```ts
// Allow if the user can read ANY lead in the batch
router.post("/leads/batch-read",
  authorize(authz, [
    {
      action: "lead.read",
      resolve: async (req) => await db.leads.findByIds(req.body.ids),
      mode: "any",
    },
  ]),
  handler
)
```

### (e) `filter` mode — no 403, narrows the list

```ts
router.get("/leads",
  authorize(authz, [
    {
      action: "lead.read",
      resolve: async (req) => await db.leads.findAll(),
      mode: "filter",   // never 403 — removes unauthorized resources
    },
  ]),
  (req, res) => {
    // Only leads the principal is allowed to read
    const leads = req.authz!.filtered["lead.read"]
    res.json(leads)
  }
)
```

### 403 / 401 response shapes

```json
// 401 — no principal resolved
{ "error": "missing_principal" }

// 403 — enforce or any mode failed
{
  "error": "forbidden",
  "principal": { "id": "s1", "tenantId": "t1", "scopes": ["lead.read"], "groups": ["channel:c1"] },
  "failures": [
    {
      "action": "lead.read",
      "resource": { "type": "lead", "id": "l-c1-13" },
      "reason": "implicit_deny",
      "matchedPolicyIds": [],
      "candidatePolicies": [
        { "id": "leads-read-mine-by-seller", "missing": ["condition did not match"] },
        { "id": "leads-read-by-admin",       "missing": ["principal — need one of: group:admins"] }
      ]
    }
  ]
}
```

---

## 12. Decision shape and explain-deny

Every `evaluate` call returns a `Decision`:

```ts
type Decision = {
  allowed: boolean
  reason: "allow" | "explicit_deny" | "implicit_deny" | "tenant_mismatch"
  matchedPolicyIds: string[]       // policies that caused the outcome
  auditedPolicyIds: string[]       // audit policies that matched (never gates)
  candidatePolicies: CandidatePolicy[]  // populated on implicit_deny
}

type CandidatePolicy = {
  id: string
  description?: string
  effect: PolicyEffect
  requiredPrincipals: string[]
  missing: string[]   // what prevented this policy from matching
}
```

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
  "matchedPolicyIds": ["leads-deny-archived"],
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

`candidatePolicies` turns debugging a 403 from guesswork into inspection. In production, surface it in your API error body — a developer receiving a 403 sees exactly which policy was the closest match and what was missing.

---

## 13. Access-control patterns — RBAC and ABAC

The engine does not enforce a single access-control model. RBAC and ABAC are both expressible, and they compose naturally in the same policy catalog.

### RBAC — Role-Based Access Control

**Groups are roles.** A group membership token (`group:admins`, `group:managers`) is all you need. Add it to `principal.groups` at authentication time, reference it in `principals`.

```ts
// Principal carries memberships
const principal: Principal = {
  id: "u1",
  tenantId: "t1",
  scopes: ["lead.read", "lead.move"],
  groups: ["managers", "channel:c1"],
  attrs: {},
}

// Policy grants by role
{
  id: "leads-delete-by-manager",
  effect: "allow",
  principals: ["group:managers"],   // ← role check
  actions: ["lead.delete"],
  resources: ["lead:*"],
}

// Policy grants by scope (capability-based RBAC)
{
  id: "leads-read-by-scope",
  effect: "allow",
  principals: ["scope:lead.read"],  // ← capability check
  actions: ["lead.read"],
  resources: ["lead:*"],
}
```

**Multiple roles in one check** — `anyOf` in `principals` is just a list; the compiled principal set handles the OR:

```ts
// Admins OR managers can approve
{
  principals: ["group:admins", "group:managers"],
  actions: ["lead.approve"],
  resources: ["lead:*"],
}
```

**Hierarchical roles** — use wildcards on groups; the bidirectionality rule applies:

```ts
// A principal carrying group:org.managers satisfies a policy requiring group:org.*
{
  principals: ["group:org.*"],  // matches group:org.managers, group:org.admins, ...
  actions: ["lead.read"],
  resources: ["lead:*"],
}
```

---

### ABAC — Attribute-Based Access Control

When role membership is not enough, use `match` conditions against `principal.attrs`, `resource.attrs`, and `context`. The attributes are resolved at eval time from the live input — no pre-computation.

```ts
// Resource carries attributes
const resource: Resource = {
  type: "lead",
  id: "l1",
  tenantId: "t1",
  attrs: {
    region: "BR-SP",
    status: "active",
    assignedTo: "u1",
    score: 82,
  },
}

// Principal carries attributes
const principal: Principal = {
  id: "u1",
  tenantId: "t1",
  scopes: ["lead.read"],
  groups: ["managers"],
  attrs: { region: "BR-SP", clearanceLevel: 2 },
}
```

```ts
// Policy: principal can only read leads in their own region
{
  id: "leads-read-own-region",
  effect: "allow",
  principals: ["scope:lead.read"],
  actions: ["lead.read"],
  resources: ["lead:*"],
  match: {
    "principal.attrs.region": "@resource.attrs.region",   // ← attribute comparison
  },
}

// Policy: only high-clearance principals read high-score leads
{
  id: "leads-read-high-score",
  effect: "allow",
  principals: ["scope:lead.read"],
  actions: ["lead.read"],
  resources: ["lead:*"],
  match: {
    allOf: [
      { "resource.score":              { "<": 80 } },   // low score — anyone allowed
    ]
  },
}
{
  id: "leads-read-high-score-gated",
  effect: "deny",
  principals: ["*"],
  actions: ["lead.read"],
  resources: ["lead:*"],
  match: {
    allOf: [
      { "resource.score":              { ">=": 80 } },  // high score
      { "principal.attrs.clearanceLevel": { "<": 2 } }, // AND low clearance → deny
    ]
  },
}

// Policy: time-scoped via context (context is request-level data)
{
  id: "leads-read-office-hours",
  effect: "allow",
  principals: ["scope:lead.read"],
  actions: ["lead.read"],
  resources: ["lead:*"],
  condition: ({ context }) => {
    const h = (context?.hour as number) ?? new Date().getHours()
    return h >= 9 && h < 18
  },
}
```

In JSON form (for the loader), express the same rules with `match` — keeping all conditions serializable without TypeScript:

```json
{
  "id": "leads-read-own-region",
  "description": "Seller reads leads only in their assigned region",
  "effect": "allow",
  "principals": ["scope:lead.read"],
  "actions": ["lead.read"],
  "resources": ["lead:*"],
  "match": {
    "principal.attrs.region": "@resource.attrs.region"
  }
}
```

---

### Combining RBAC and ABAC

The patterns are not mutually exclusive. A single policy — or a set of cooperating policies — can gate access on both role membership **and** attribute conditions.

```ts
// "Managers can reassign leads, but only within their own channel"
// RBAC: group:managers   +   ABAC: channelId must match
{
  id: "leads-reassign-by-manager-in-channel",
  effect: "allow",
  principals: ["group:managers"],                // ← RBAC: role gate
  actions: ["lead.reassign"],
  resources: ["lead:*"],
  match: {
    "resource.channelId": "@principal.groups",   // ← ABAC: channel attribute
  },
}

// "Only senior managers can delete leads created more than 30 days ago"
// RBAC: group:senior-managers   +   ABAC: resource age
{
  id: "leads-delete-old-by-senior-manager",
  effect: "allow",
  principals: ["group:senior-managers"],
  actions: ["lead.delete"],
  resources: ["lead:*"],
  match: {
    "resource.ageInDays": { ">=": 30 },
  },
}

// "Admins can do anything, but nobody touches archived leads"
// RBAC: group:admins allow   +   ABAC: deny override on attribute
{
  id: "admins-all",
  effect: "allow",
  principals: ["group:admins"],
  actions: ["**"],
  resources: ["*"],
},
{
  id: "deny-archived-writes",
  effect: "deny",                                // deny wins over allow
  principals: ["*"],
  actions: ["lead.update", "lead.delete"],
  resources: ["lead:*"],
  match: { "resource.status": "archived" },      // ← ABAC: attribute gate
}
```

---

### Choosing between the two

| Need | Pattern | Mechanism |
|---|---|---|
| Coarse-grained roles ("admins can X") | RBAC | `principals: ["group:admins"]` |
| Capability tokens ("bearer of lead.read can X") | RBAC (scope-based) | `principals: ["scope:lead.read"]` |
| "Only in the same channel" | ABAC | `match: { "resource.channelId": "@principal.groups" }` |
| "Only on unowned leads" | ABAC | `match: { "resource.assignedTo": null }` |
| "Only by the assignee" | ABAC | `match: { "resource.assignedTo": "@principal.id" }` |
| "Only above clearance level N" | ABAC | `match: { "principal.attrs.clearanceLevel": { ">=": N } }` |
| "Manager in the right channel" | RBAC + ABAC | `principals: ["group:managers"]` + `match: { "resource.channelId": ... }` |

**Guidance:** start with RBAC — it is easy to audit ("who has the admin role?"). Layer ABAC conditions when you need to narrow access beyond what group membership can express. Three fine-grained ABAC policies are easier to reason about than a single catch-all that tries to cover everything.

---

## 14. Design decisions

| Decision | Rationale |
|---|---|
| No `roles` field | Redundant with `groups`. A role is just a named group. Fewer concepts, same power. |
| `tenantId: string \| null` on both sides | First-class, not an `attr`. `null` has explicit semantics (platform / global). Isolation is unconditional. |
| Scopes and groups in the same compiled set | `scope:lead.read`, `group:admins`, `user:s1` are all just patterns. One `matchAny` pass covers everything. |
| Actions are dot-namespaced | Same namespace as scopes. A principal with `scope:lead.**` satisfies any action in the lead namespace without extra mapping. |
| Globstar bidirectionality | A principal with `scope:lead.**` satisfies `scope:lead.read`. Enables platform principals to carry wildcard scopes without special-casing. |
| Match DSL is Mongo-style | Reads like a query, not a predicate. Serializable to JSON, survives restarts, editable without a TypeScript compiler. |
| `@ref` for cross-field comparisons | Avoids hardcoded values when comparing two dynamic fields. `"@principal.groups"` resolves at eval time. |
| `anyOf` collapses policy explosion | Three pool/owner/shared read policies collapse to one. |
| `audit` is orthogonal to allow/deny | Never changes the gate. The shadow rollout primitive — ship as audit, observe, promote to deny. |
| `candidatePolicies` in implicit_deny | Explain-deny without a separate endpoint. Same call returns the closest-matching policies and what was missing. |
| `customConditions` fail at load time | An unresolved name throws at startup. Fail fast, never silently at eval time. |
| No file watcher | `replacePolicies()` is the API. Wire it to inotify or a config endpoint yourself. |

---

## 15. Non-goals

- **Not a production library.** No versioning, semver, or support contract.
- **Not Express-specific.** The middleware uses duck-typed `req`/`res`/`next`.
- **Not Cedar, Rego, or XACML.** No policy language parser, no rule graph.
- **Not a parent-graph engine.** No resource tree (`org → channel → lead`). Model hierarchy through `attrs` and match conditions.
- **Not an obligation engine.** Policies say allow/deny/audit. They do not trigger side effects.
- **Not a priority engine.** The only precedence is `deny > allow`. No numeric priority between same-effect policies.
- **Not a file watcher.** `loadPoliciesFromDir` reads once.
- **Not YAML or JSON5.** Standard JSON only.
