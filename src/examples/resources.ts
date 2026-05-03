import type { Resource } from "../engine/types"

export const RESOURCES = {
  // Channel c1 leads — tenant t1
  pool_lead_c1: {
    type: "lead", id: "l-c1-01",
    tenantId: "t1",
    attrs: { channelId: "channel:c1", status: "novo", assignedTo: null },
  },
  ana_lead_c1: {
    type: "lead", id: "l-c1-08",
    tenantId: "t1",
    attrs: { channelId: "channel:c1", status: "contatado", assignedTo: "s1" },
  },
  bruno_lead_c1: {
    type: "lead", id: "l-c1-13",
    tenantId: "t1",
    attrs: { channelId: "channel:c1", status: "contatado", assignedTo: "s2" },
  },
  shared_lead_c1: {
    type: "lead", id: "l-c1-20",
    tenantId: "t1",
    attrs: { channelId: "channel:c1", status: "contatado", assignedTo: "s2", sharedWith: "s1" },
  },

  // Channel c2 lead — same tenant t1
  pool_lead_c2: {
    type: "lead", id: "l-c2-01",
    tenantId: "t1",
    attrs: { channelId: "channel:c2", status: "novo", assignedTo: null },
  },

  // Cross-tenant lead — demonstrates tenant_mismatch
  foreign_lead: {
    type: "lead", id: "l-t2-01",
    tenantId: "t2",
    attrs: { channelId: "channel:c1", status: "novo", assignedTo: null },
  },

  // Short-ID leads — demonstrate ? and [abc] wildcards
  // lead:l? matches l1, l2, l3 (exactly 1-char suffix) but NOT l12 (2 chars)
  // lead:l[12] matches l1, l2 but NOT l30 (2-char suffix starting with 3)
  lead_l1:  { type: "lead", id: "l1",  tenantId: "t1", attrs: {} },
  lead_l2:  { type: "lead", id: "l2",  tenantId: "t1", attrs: {} },
  lead_l30: { type: "lead", id: "l30", tenantId: "t1", attrs: {} },
  lead_l12: { type: "lead", id: "l12", tenantId: "t1", attrs: {} },

  // Restricted lead — demonstrates explicit deny via match DSL
  restricted_lead_c1: {
    type: "lead", id: "l-c1-99",
    tenantId: "t1",
    attrs: { channelId: "channel:c1", status: "novo", assignedTo: null, restricted: true },
  },

  // Platform resources (tenantId: null = global)
  channel_c1:      { type: "channel",  id: "c1",     tenantId: "t1", attrs: {} },
  channel_c2:      { type: "channel",  id: "c2",     tenantId: "t1", attrs: {} },
  global_settings: { type: "settings", id: "global", tenantId: null, attrs: {} },
  policy_catalog:  { type: "policy",   id: "global", tenantId: null, attrs: {} },
} satisfies Record<string, Resource>
