import type { Principal, Resource } from "../engine/types"
import { PRINCIPALS } from "./principals"
import { RESOURCES } from "./resources"

export type ExampleCase = {
  label: string
  principal: Principal
  action: string
  resource: Resource
  expectedAllowed: boolean
  note?: string
}

export const CASES: ExampleCase[] = [
  // ── ALLOW ──────────────────────────────────────────────────────────────────

  {
    label: "Seller reads pool lead in their own channel",
    principal: PRINCIPALS.ana_seller_c1,
    action: "lead.read",
    resource: RESOURCES.pool_lead_c1,
    expectedAllowed: true,
  },
  {
    label: "Seller reads their own assigned lead",
    principal: PRINCIPALS.ana_seller_c1,
    action: "lead.read",
    resource: RESOURCES.ana_lead_c1,
    expectedAllowed: true,
  },
  {
    label: "Seller reads a lead explicitly shared with them",
    principal: PRINCIPALS.ana_seller_c1,
    action: "lead.read",
    resource: RESOURCES.shared_lead_c1,
    expectedAllowed: true,
  },
  {
    label: "Seller claims a pool lead",
    principal: PRINCIPALS.ana_seller_c1,
    action: "lead.claim",
    resource: RESOURCES.pool_lead_c1,
    expectedAllowed: true,
  },
  {
    label: "Seller moves their own lead through the funnel",
    principal: PRINCIPALS.ana_seller_c1,
    action: "lead.move",
    resource: RESOURCES.ana_lead_c1,
    expectedAllowed: true,
  },
  {
    label: "Manager reads another seller's lead in their channel",
    principal: PRINCIPALS.eva_manager_c1,
    action: "lead.read",
    resource: RESOURCES.bruno_lead_c1,
    expectedAllowed: true,
  },
  {
    label: "Manager moves another seller's lead in their channel",
    principal: PRINCIPALS.eva_manager_c1,
    action: "lead.move",
    resource: RESOURCES.bruno_lead_c1,
    expectedAllowed: true,
  },
  {
    label: "Admin reads any lead in any channel",
    principal: PRINCIPALS.admin_t1,
    action: "lead.read",
    resource: RESOURCES.pool_lead_c2,
    expectedAllowed: true,
  },
  {
    label: "Admin moves any lead",
    principal: PRINCIPALS.admin_t1,
    action: "lead.move",
    resource: RESOURCES.bruno_lead_c1,
    expectedAllowed: true,
  },
  {
    label: "Admin reads global settings",
    principal: PRINCIPALS.admin_t1,
    action: "settings.read",
    resource: RESOURCES.global_settings,
    expectedAllowed: true,
  },

  // ── GLOBSTAR WILDCARDS ─────────────────────────────────────────────────────

  {
    label: "** in actions: admin performs lead.move.funnel via policy lead.**",
    principal: PRINCIPALS.admin_t1,
    action: "lead.move.funnel",
    resource: RESOURCES.pool_lead_c1,
    expectedAllowed: true,
    note: "policy uses actions: ['lead.**'] — crosses multiple segments",
  },
  {
    label: "** bidirectional: platform_admin (scope:lead.**) satisfies policy scope:lead.read",
    principal: PRINCIPALS.platform_admin,
    action: "lead.read",
    resource: RESOURCES.pool_lead_c1,
    expectedAllowed: true,
    note: "principal carries scope:lead.** → satisfies any lead.<action>",
  },
  {
    label: "* in actions: group:cross-readers reads leads via policy actions:['*.read']",
    principal: PRINCIPALS.cross_reader,
    action: "lead.read",
    resource: RESOURCES.pool_lead_c1,
    expectedAllowed: true,
    note: "policy uses actions: ['*.read'] — any single segment before .read",
  },
  {
    label: "* in actions: group:cross-readers cannot move leads (*.read does not match lead.move)",
    principal: PRINCIPALS.cross_reader,
    action: "lead.move",
    resource: RESOURCES.pool_lead_c1,
    expectedAllowed: false,
    note: "*.read does not match lead.move",
  },
  {
    label: "{a,b} in principals: scope:lead.{read,claim} matches scope:lead.read",
    principal: PRINCIPALS.ana_seller_c1,
    action: "lead.read",
    resource: RESOURCES.pool_lead_c1,
    expectedAllowed: true,
    note: "alternation in policy; ana has scope:lead.read which matches lead.{read,claim}",
  },
  {
    label: "? in resources: lead:l? matches lead:l1 (2-char id)",
    principal: PRINCIPALS.ana_seller_c1,
    action: "lead.read",
    resource: RESOURCES.lead_l1,
    expectedAllowed: true,
    note: "policy uses resources: ['lead:l?'] — id exactly 2 chars",
  },
  {
    label: "? in resources: lead:l? does NOT match lead:l12 (3-char id)",
    principal: PRINCIPALS.ana_seller_c1,
    action: "lead.read",
    resource: RESOURCES.lead_l12,
    expectedAllowed: false,
    note: "? matches exactly 1 char; l12 has 2 chars after l",
  },
  {
    label: "[abc] in resources: lead:l[12] matches lead:l1",
    principal: PRINCIPALS.ana_seller_c1,
    action: "lead.read",
    resource: RESOURCES.lead_l1,
    expectedAllowed: true,
    note: "policy uses resources: ['lead:l[12]'] — l1 is in the set",
  },
  {
    label: "[abc] in resources: lead:l[12] does NOT match lead:l30",
    principal: PRINCIPALS.ana_seller_c1,
    action: "lead.read",
    resource: RESOURCES.lead_l30,
    expectedAllowed: false,
    note: "l30 has a 2-char suffix — matches neither l? nor l[12]",
  },

  // ── TENANT GUARD ───────────────────────────────────────────────────────────

  {
    label: "Cross-tenant seller cannot read a lead from another tenant (tenant_mismatch)",
    principal: PRINCIPALS.foreign_seller,
    action: "lead.read",
    resource: RESOURCES.pool_lead_c1,
    expectedAllowed: false,
    note: "foreign_seller.tenantId=t2 vs pool_lead_c1.tenantId=t1 → tenant_mismatch before any policy",
  },
  {
    label: "Platform admin (tenantId=null) reads a lead from any tenant",
    principal: PRINCIPALS.platform_admin,
    action: "lead.read",
    resource: RESOURCES.pool_lead_c2,
    expectedAllowed: true,
    note: "platform_admin.tenantId=null → bypasses tenant guard; has scope:lead.**",
  },
  {
    label: "Tenant admin accesses global settings (resource tenantId=null)",
    principal: PRINCIPALS.admin_t1,
    action: "settings.read",
    resource: RESOURCES.global_settings,
    expectedAllowed: true,
    note: "resource.tenantId=null → bypasses tenant guard; admin has scope:settings.read",
  },

  // ── AUDIT EFFECT (task 8) ──────────────────────────────────────────────────

  {
    label: "audit: seller reads pool lead — ALLOW but audit policy fires",
    principal: PRINCIPALS.ana_seller_c1,
    action: "lead.read",
    resource: RESOURCES.pool_lead_c1,
    expectedAllowed: true,
    note: "audit-lead-reads-by-seller matches: allowed=true, auditedPolicyIds=[audit-lead-reads-by-seller]",
  },
  {
    label: "audit: admin reads lead — ALLOW but both audit policies fire",
    principal: PRINCIPALS.admin_t1,
    action: "lead.read",
    resource: RESOURCES.pool_lead_c1,
    expectedAllowed: true,
    note: "both audit-lead-reads-cross-channel and leads-any-action-by-admin-doublestar match for audits",
  },

  // ── IMPLICIT DENY ──────────────────────────────────────────────────────────

  {
    label: "Seller cannot read another seller's lead (not in pool, not assigned to them)",
    principal: PRINCIPALS.ana_seller_c1,
    action: "lead.read",
    resource: RESOURCES.bruno_lead_c1,
    expectedAllowed: false,
    note: "implicit_deny — policy exists but conditions do not match",
  },
  {
    label: "Seller cannot read a lead from a different channel",
    principal: PRINCIPALS.ana_seller_c1,
    action: "lead.read",
    resource: RESOURCES.pool_lead_c2,
    expectedAllowed: false,
    note: "implicit_deny — channelId not in Ana's groups",
  },
  {
    label: "Seller cannot move another seller's lead",
    principal: PRINCIPALS.ana_seller_c1,
    action: "lead.move",
    resource: RESOURCES.bruno_lead_c1,
    expectedAllowed: false,
    note: "implicit_deny — assignedTo !== ana.id",
  },
  {
    label: "Manager cannot claim a lead (no scope lead.claim)",
    principal: PRINCIPALS.eva_manager_c1,
    action: "lead.claim",
    resource: RESOURCES.pool_lead_c1,
    expectedAllowed: false,
    note: "implicit_deny — manager has lead.move but not lead.claim",
  },
  {
    label: "Manager cannot read a lead from a different channel",
    principal: PRINCIPALS.eva_manager_c1,
    action: "lead.read",
    resource: RESOURCES.pool_lead_c2,
    expectedAllowed: false,
    note: "implicit_deny — c2 not in Eva's groups",
  },
  {
    label: "Seller cannot read global settings",
    principal: PRINCIPALS.ana_seller_c1,
    action: "settings.read",
    resource: RESOURCES.global_settings,
    expectedAllowed: false,
    note: "implicit_deny — seller does not have scope settings.read",
  },
  {
    label: "Seller from channel c2 cannot read a lead from channel c1",
    principal: PRINCIPALS.carla_seller_c2,
    action: "lead.read",
    resource: RESOURCES.pool_lead_c1,
    expectedAllowed: false,
    note: "implicit_deny — c1 not in Carla's groups",
  },
]

// ── MATCH DSL CASES (tasks 4–5) ───────────────────────────────────────────────
// Evaluated against MATCH_DSL_POLICIES only (separate authz instance in run.ts).

export const MATCH_DSL_CASES: ExampleCase[] = [
  // Task 4 — basic sigil forms

  {
    label: "match @ref: seller reads their own lead (channelId + assignedTo == @principal.id)",
    principal: PRINCIPALS.ana_seller_c1,
    action: "lead.read",
    resource: RESOURCES.ana_lead_c1,
    expectedAllowed: true,
    note: "resource.channelId in @principal.groups AND resource.assignedTo == @principal.id",
  },
  {
    label: "match null: seller reads a pool lead (assignedTo === null)",
    principal: PRINCIPALS.ana_seller_c1,
    action: "lead.read",
    resource: RESOURCES.pool_lead_c1,
    expectedAllowed: true,
    note: "resource.assignedTo: null — unowned pool lead in the correct channel",
  },
  {
    label: "match deny: nobody reads a lead with restricted=true (explicit deny)",
    principal: PRINCIPALS.ana_seller_c1,
    action: "lead.read",
    resource: RESOURCES.restricted_lead_c1,
    expectedAllowed: false,
    note: "match-restricted-deny: resource.restricted === true → explicit_deny before any allow",
  },
  {
    label: "match startsWith (admin group): admin reads a l-c1 lead",
    principal: PRINCIPALS.admin_t1,
    action: "lead.read",
    resource: RESOURCES.pool_lead_c1,
    expectedAllowed: true,
    note: "match-id-startswith: group:admins + id.startsWith('l-c1')",
  },

  // Task 5 — operators + anyOf composition

  {
    label: "match anyOf: seller reads a shared lead (anyOf pool|owner|shared)",
    principal: PRINCIPALS.ana_seller_c1,
    action: "lead.read",
    resource: RESOURCES.shared_lead_c1,
    expectedAllowed: true,
    note: "match-lead-read-consolidated: shared_lead_c1.sharedWith === s1 → anyOf[2] passes",
  },
  {
    label: "match in operator: lead with status 'novo' passes in ['novo','contatado']",
    principal: PRINCIPALS.ana_seller_c1,
    action: "lead.read",
    resource: RESOURCES.pool_lead_c1,
    expectedAllowed: true,
    note: "match-status-in-operator: status in ['novo', 'contatado']",
  },
  {
    label: "match in operator: lead with status 'contatado' passes in ['novo','contatado']",
    principal: PRINCIPALS.ana_seller_c1,
    action: "lead.read",
    resource: RESOURCES.ana_lead_c1,
    expectedAllowed: true,
    note: "match-status-in-operator: status in ['novo', 'contatado'] AND anyOf owner branch",
  },
  {
    label: "match startsWith: admin reads lead with id starting with 'l-c1'",
    principal: PRINCIPALS.admin_t1,
    action: "lead.read",
    resource: RESOURCES.pool_lead_c1,
    expectedAllowed: true,
    note: "match-id-startswith: pool_lead_c1.id = l-c1-01",
  },
  {
    label: "match startsWith: admin cannot read a c2 lead via the startsWith policy",
    principal: PRINCIPALS.admin_t1,
    action: "lead.read",
    resource: RESOURCES.pool_lead_c2,
    expectedAllowed: false,
    note: "pool_lead_c2.id = l-c2-01 — does not start with 'l-c1'",
  },
]
