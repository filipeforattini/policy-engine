import { RawPolicy } from "./authz"

export const policies: RawPolicy[] = [
  {
    id: "dev-api-manage",
    effect: "allow",
    principals: ["role:developer", "user:admin"],
    actions: ["create", "read", "update", "delete"],
    resources: ["api:*"],
  },
  {
    id: "dev-key-manage",
    effect: "allow",
    principals: ["role:developer", "user:admin"],
    actions: ["create", "read", "update", "delete"],
    resources: ["apikey:*"],
  },
  {
    id: "global-freeze-delete-api",
    effect: "deny",
    principals: ["*"],
    actions: ["delete"],
    resources: ["api:*"],
  },
  {
    id: "admin-policy-edit",
    effect: "allow",
    principals: ["role:admin", "user:admin"],
    actions: ["read", "update"],
    resources: ["policy:*"],
  },
]
