import type { JsonPolicy, Policy } from "../engine/types"
import { jsonPolicyToPolicy } from "../engine/createAuthz"

// Match DSL demo policies used by the declarative examples suite (tasks 4–5).
// The canonical policies live in src/examples/policies/*.json (loaded by run.ts via loadPoliciesFromDir).

const MATCH_DSL_JSON: JsonPolicy[] = [
  // Task 4 — basic sigil forms
  {
    id: "match-channel-scope",
    description: "match DSL @ref: read lead in own channel where assignedTo == principal",
    effect: "allow",
    principals: ["scope:lead.read"],
    actions: ["lead.read"],
    resources: ["lead:*"],
    match: {
      "resource.channelId": "@principal.groups",
      "resource.assignedTo": "@principal.id",
    },
  },
  {
    id: "match-pool-null-check",
    description: "match DSL null: read pool lead (assignedTo === null)",
    effect: "allow",
    principals: ["scope:lead.read"],
    actions: ["lead.read"],
    resources: ["lead:*"],
    match: {
      "resource.channelId": "@principal.groups",
      "resource.assignedTo": null,
    },
  },
  {
    id: "match-restricted-deny",
    description: "match DSL explicit deny: block any lead with restricted=true",
    effect: "deny",
    principals: ["*"],
    actions: ["lead.read"],
    resources: ["lead:*"],
    match: { "resource.restricted": true },
  },

  // Task 5 — operators + anyOf composition
  {
    id: "match-lead-read-consolidated",
    description: "match DSL anyOf: consolidates pool + owner + shared into one policy",
    effect: "allow",
    principals: ["scope:lead.read"],
    actions: ["lead.read"],
    resources: ["lead:*"],
    match: {
      anyOf: [
        { "resource.channelId": "@principal.groups", "resource.assignedTo": null },
        { "resource.channelId": "@principal.groups", "resource.assignedTo": "@principal.id" },
        { "resource.channelId": "@principal.groups", "resource.sharedWith": "@principal.id" },
      ],
    },
  },
  {
    id: "match-status-in-operator",
    description: "match DSL in operator: status in ['novo', 'contatado']",
    effect: "allow",
    principals: ["scope:lead.read"],
    actions: ["lead.read"],
    resources: ["lead:*"],
    match: {
      "resource.channelId": "@principal.groups",
      "resource.status": { in: ["novo", "contatado"] },
    },
  },
  {
    id: "match-id-startswith",
    description: "match DSL startsWith: admin reads leads with id starting with 'l-c1'",
    effect: "allow",
    principals: ["group:admins"],
    actions: ["lead.read"],
    resources: ["lead:*"],
    match: { "resource.id": { startsWith: "l-c1" } },
  },
  {
    id: "match-email-regex",
    description: "match DSL regex: seller email must be a stone.com.br address",
    effect: "allow",
    principals: ["group:admins"],
    actions: ["seller.read"],
    resources: ["seller:*"],
    match: { "resource.email": { regex: "^.+@stone\\.com\\.br$" } },
  },
]

export const MATCH_DSL_POLICIES: Policy[] = MATCH_DSL_JSON.map(jsonPolicyToPolicy)
