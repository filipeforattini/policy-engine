import type { Principal } from "../engine/types"

export const PRINCIPALS = {
  // Platform admin — no tenantId (crosses tenants)
  platform_admin: {
    id: "platform-admin",
    tenantId: null,
    scopes: ["lead.**", "channel.**", "seller.**", "settings.**", "policy.**"],
    groups: ["admins"],
  },

  // Tenant t1 admin
  admin_t1: {
    id: "admin-t1",
    tenantId: "t1",
    scopes: [
      "lead.read", "lead.claim", "lead.move", "lead.write",
      "lead.delete", "lead.share",
      "channel.read", "channel.write", "channel.delete",
      "seller.read", "seller.write", "seller.delete",
      "settings.read", "settings.write",
      "policy.read", "policy.write",
    ],
    groups: ["admins"],
  },

  // Channel c1 manager in tenant t1
  eva_manager_c1: {
    id: "m1",
    tenantId: "t1",
    scopes: ["lead.read", "lead.move", "lead.share", "channel.read"],
    groups: ["channel:c1"],
    attrs: { role: "manager" },
  },

  // Channel c1 seller in tenant t1
  ana_seller_c1: {
    id: "s1",
    tenantId: "t1",
    scopes: ["lead.read", "lead.claim", "lead.move", "lead.share"],
    groups: ["channel:c1"],
  },

  // Channel c1 seller (Ana's peer)
  bruno_seller_c1: {
    id: "s2",
    tenantId: "t1",
    scopes: ["lead.read", "lead.claim", "lead.move"],
    groups: ["channel:c1"],
  },

  // Channel c2 seller (different channel, same tenant)
  carla_seller_c2: {
    id: "s3",
    tenantId: "t1",
    scopes: ["lead.read", "lead.claim", "lead.move"],
    groups: ["channel:c2"],
  },

  // User in cross-readers group — demonstrates *.read in actions
  cross_reader: {
    id: "x1",
    tenantId: "t1",
    scopes: [],
    groups: ["cross-readers"],
  },

  // User from another tenant — demonstrates cross-tenant block
  foreign_seller: {
    id: "f1",
    tenantId: "t2",
    scopes: ["lead.read"],
    groups: ["channel:c1"],
  },
} satisfies Record<string, Principal>
