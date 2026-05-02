import crypto from "crypto"
import express from "express"
import path from "path"
import jwt from "jsonwebtoken"
import { createAuthz, RawPolicy, RouteCheck } from "./authz"
import { policies as initialPolicies } from "./policies"

type User = {
  id: string
  roles: string[]
  name: string
}

type Api = {
  id: string
  tenantId: string
  environment: "dev" | "prod"
  ownerId: string
}

type ApiKey = {
  id: string
  apiId: string
  ownerId: string
  label: string
}

type Principal = {
  id: string
  roles: string[]
  attrs?: Record<string, unknown>
}

type PolicyInput = {
  id: string
  effect: "allow" | "deny"
  principals: string[]
  actions: string[]
  resources: string[]
}

const users: Record<string, User> = {
  u1: { id: "u1", name: "Ana", roles: ["developer"] },
  u2: { id: "u2", name: "Bruno", roles: ["viewer"] },
  admin: { id: "admin", name: "Admin", roles: ["admin"] },
}

const apiStore: Record<string, Api> = {
  "api-1": { id: "api-1", tenantId: "t1", environment: "prod", ownerId: "u1" },
  "api-2": { id: "api-2", tenantId: "t1", environment: "dev", ownerId: "u2" },
}

const keyStore: Record<string, ApiKey> = {
  "k-1": { id: "k-1", apiId: "api-1", ownerId: "u1", label: "Principal key" },
  "k-2": { id: "k-2", apiId: "api-1", ownerId: "u2", label: "Fallback key" },
}

type AuthContext = {
  principal: Principal
  context?: Record<string, unknown>
  filtered?: Record<string, ApiKey[]>
}

type AuthRequest = express.Request & { authz?: AuthContext }

const JWT_SECRET = "dev-authz-secret"
const JWT_EXPIRES_IN = "8h"

function createToken(user: User) {
  const payload = {
    name: user.name,
    roles: user.roles,
  }
  return jwt.sign(payload, JWT_SECRET, {
    subject: user.id,
    expiresIn: JWT_EXPIRES_IN,
  })
}

const app = express()
app.use(express.json())
app.use(express.static(path.join(process.cwd(), "public")))

let policyCatalog: RawPolicy[] = initialPolicies.map((policy) => ({
  id: policy.id,
  effect: policy.effect,
  principals: [...policy.principals],
  actions: [...policy.actions],
  resources: [...policy.resources],
}))

let authz = createAuthz({ policies: policyCatalog })

function rebuildAuthz(nextPolicies: RawPolicy[]) {
  policyCatalog = nextPolicies
  authz = createAuthz({ policies: policyCatalog })
}

function parsePolicies(input: unknown): RawPolicy[] {
  if (!Array.isArray(input)) {
    throw new Error("policies precisa ser um array")
  }

  return input.map((entry, index) => {
    const policy = entry as Partial<PolicyInput> & { [key: string]: unknown }

    if (!policy?.id || typeof policy.id !== "string") {
      throw new Error(`policy[${index}]: id inválido`)
    }
    if (policy.effect !== "allow" && policy.effect !== "deny") {
      throw new Error(`policy[${index}]: effect precisa ser allow | deny`)
    }
    if (!Array.isArray(policy.principals)) {
      throw new Error(`policy[${index}]: principals precisa ser array`)
    }
    if (!Array.isArray(policy.actions)) {
      throw new Error(`policy[${index}]: actions precisa ser array`)
    }
    if (!Array.isArray(policy.resources)) {
      throw new Error(`policy[${index}]: resources precisa ser array`)
    }

    return {
      id: policy.id,
      effect: policy.effect,
      principals: policy.principals.map((value) => String(value)),
      actions: policy.actions.map((value) => String(value)),
      resources: policy.resources.map((value) => String(value)),
    }
  })
}

const withAuth: express.RequestHandler = (req, res, next) => {
  const rawAuth = req.header("authorization") ?? ""
  const token = rawAuth.startsWith("Bearer ") ? rawAuth.slice(7).trim() : ""
  if (!token) {
    return res.status(401).json({ error: "missing_token" })
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET) as jwt.JwtPayload & {
      name?: string
      roles?: string[]
    }

    const principalId = decoded.sub
    if (!principalId) {
      return res.status(401).json({ error: "invalid_token" })
    }

    const user = users[principalId]
    if (!user) {
      return res.status(401).json({ error: "unknown_user" })
    }

    req.authz = {
      principal: {
        id: user.id,
        roles: user.roles,
        attrs: {
          name: user.name,
        },
      },
      context: {
        globalDeleteFreeze: false,
      },
      filtered: {},
    }

    return next()
  } catch {
    return res.status(401).json({ error: "invalid_token" })
  }
}

const authorizeRoute = (checks: RouteCheck[]) => {
  return async (req: AuthRequest, res: express.Response, next: express.NextFunction) => {
    return authz.authorize(checks)(req, res, next)
  }
}

const buildPolicyResource = (id: string) => ({ type: "policy", id })
const buildApiResource = (api: Api) => ({ type: "api", id: api.id, attrs: api })
const buildApiKeyResource = (key: ApiKey) => ({
  type: "apikey",
  id: key.id,
  attrs: key,
})

app.get("/health", (_req, res) => {
  res.json({ ok: true })
})

app.post("/auth/token", (req, res) => {
  const userId = String(req.body?.userId || "")
  const user = users[userId]

  if (!user) {
    return res.status(404).json({ error: "user_not_found" })
  }

  const token = createToken(user)
  return res.json({
    accessToken: token,
    tokenType: "Bearer",
    expiresIn: JWT_EXPIRES_IN,
    user: {
      id: user.id,
      name: user.name,
      roles: user.roles,
    },
  })
})

app.get("/api/policies", withAuth, authorizeRoute([
  {
    action: "read",
    resolve: async () => buildPolicyResource("global"),
  },
]), (_req, res) => {
  const serializable = policyCatalog.map(({ ...rest }) => rest)
  res.json(serializable)
})

app.put("/api/policies", withAuth, authorizeRoute([
  {
    action: "update",
    resolve: async () => buildPolicyResource("global"),
  },
]), async (req, res) => {
  try {
    const nextPolicies = parsePolicies(req.body)
    rebuildAuthz(nextPolicies)
    res.json({ ok: true, count: nextPolicies.length })
  } catch (error) {
    const requestId = crypto.randomUUID()
    const detail = error instanceof Error ? error.message : String(error)
    console.error(
      JSON.stringify({
        level: "error",
        event: "policy_parse_failed",
        requestId,
        principalId: (req as AuthRequest).authz?.principal.id,
        detail,
      }),
    )
    return res.status(400).json({ error: "invalid_policy_format", requestId })
  }
})

app.get("/api/me", withAuth, (req: AuthRequest, res) => {
  res.json({ principal: req.authz?.principal, context: req.authz?.context })
})

app.get("/api/resources", withAuth, (req, res) => {
  res.json({
    apis: Object.values(apiStore),
    keys: Object.values(keyStore),
  })
})

app.post("/api/resources/apis", withAuth, authorizeRoute([
  {
    action: "create",
    resolve: async (req) => {
      const body = req.body as Partial<Api> & { id?: string }
      return {
        type: "api",
        id: body.id ?? `api-${Date.now()}`,
        attrs: {
          tenantId: body.tenantId ?? "t1",
          environment: body.environment ?? "dev",
          ownerId: body.ownerId ?? req.authz?.principal.id ?? "u1",
        },
      }
    },
  },
]), (req, res) => {
  const body = req.body as Partial<Api>
  const id = body.id ?? `api-${Date.now()}`
  if (apiStore[id]) {
    return res.status(409).json({ error: "api_exists" })
  }
  const environment = body.environment === "prod" ? "prod" : "dev"

  const api: Api = {
    id,
    tenantId: body.tenantId ?? "t1",
    environment,
    ownerId: body.ownerId ?? req.authz!.principal.id,
  }

  apiStore[id] = api
  return res.status(201).json(api)
})

app.get("/api/resources/apis/:apiId", withAuth, authorizeRoute([
  {
    action: "read",
    resolve: async (req) => {
      const apiId = String(req.params.apiId)
      const api = apiStore[apiId]
      return {
        type: "api",
        id: api?.id ?? apiId,
        attrs: api ?? {},
      }
    },
  },
]), (req, res) => {
  const api = apiStore[String(req.params.apiId)]
  if (!api) {
    return res.status(404).json({ error: "not_found" })
  }
  res.json(api)
})

app.put("/api/resources/apis/:apiId", withAuth, authorizeRoute([
  {
    action: "update",
    resolve: async (req) => {
      const api = apiStore[String(req.params.apiId)]
      return buildApiResource(
        api ?? {
          id: String(req.params.apiId),
          tenantId: "t1",
          environment: "dev",
          ownerId: "u1",
        },
      )
    },
  },
]), (req, res) => {
  const api = apiStore[String(req.params.apiId)]
  if (!api) {
    return res.status(404).json({ error: "not_found" })
  }
  const body = req.body as Partial<Api>
  if (body.environment === "prod" || body.environment === "dev") {
    api.environment = body.environment
  }
  if (body.ownerId) {
    api.ownerId = body.ownerId
  }
  if (body.tenantId) {
    api.tenantId = body.tenantId
  }
  res.json(api)
})

app.delete("/api/resources/apis/:apiId", withAuth, authorizeRoute([
  {
    action: "delete",
    resolve: async (req) => {
      const api = apiStore[String(req.params.apiId)]
      return buildApiResource(
        api ?? {
          id: String(req.params.apiId),
          tenantId: "t1",
          environment: "dev",
          ownerId: "u1",
        },
      )
    },
  },
]), (req, res) => {
  const apiId = String(req.params.apiId)
  if (!apiStore[apiId]) {
    return res.status(404).json({ error: "not_found" })
  }
  delete apiStore[apiId]
  Object.keys(keyStore).forEach((keyId) => {
    if (keyStore[keyId].apiId === apiId) {
      delete keyStore[keyId]
    }
  })
  res.json({ ok: true, deletedApiId: apiId })
})

app.get("/api/resources/apis/:apiId/keys", withAuth, (req, res) => {
  const apiId = String(req.params.apiId)
  const keys = Object.values(keyStore).filter((key) => key.apiId === apiId)
  res.json({ keys })
})

app.post("/api/resources/apis/:apiId/keys", withAuth, authorizeRoute([
  {
    action: "create",
    resolve: async (req) => {
      const api = apiStore[String(req.params.apiId)]
      return buildApiResource(
        api ?? {
          id: String(req.params.apiId),
          tenantId: "t1",
          environment: "dev",
          ownerId: req.authz?.principal.id ?? "u1",
        },
      )
    },
  },
  {
    action: "create",
    resolve: async (req) => {
      const keyId = String(req.body.keyId ?? `k-${Date.now()}`)
      return buildApiKeyResource({
        id: keyId,
        apiId: String(req.params.apiId),
        ownerId: (req.body.ownerId as string) ?? (req.authz?.principal.id ?? "u1"),
        label: (req.body.label as string) ?? "new key",
      })
    },
  },
]), (req, res) => {
  const apiId = String(req.params.apiId)
  const api = apiStore[apiId]
  if (!api) {
    return res.status(404).json({ error: "api_not_found" })
  }

  const keyId = String(req.body.keyId ?? `k-${Date.now()}`)
  if (keyStore[keyId]) {
    return res.status(409).json({ error: "key_exists" })
  }

  const key: ApiKey = {
    id: keyId,
    apiId,
    ownerId: req.body.ownerId ?? req.authz?.principal.id ?? "u1",
    label: req.body.label ?? "new key",
  }
  keyStore[key.id] = key
  res.status(201).json(key)
})

app.put("/api/resources/apis/:apiId/keys/:keyId", withAuth, authorizeRoute([
  {
    action: "update",
    resolve: async (req) => {
      const api = apiStore[String(req.params.apiId)]
      return buildApiResource(
        api ?? {
          id: String(req.params.apiId),
          tenantId: "t1",
          environment: "dev",
          ownerId: req.authz?.principal.id ?? "u1",
        },
      )
    },
  },
  {
    action: "update",
    resolve: async (req) => {
      const key = keyStore[String(req.params.keyId)]
      return buildApiKeyResource(
        key ?? {
          id: String(req.params.keyId),
          apiId: String(req.params.apiId),
          ownerId: req.authz?.principal.id ?? "u1",
          label: "",
        },
      )
    },
  },
]), (req, res) => {
  const key = keyStore[String(req.params.keyId)]
  if (!key || key.apiId !== String(req.params.apiId)) {
    return res.status(404).json({ error: "not_found" })
  }

  const nextLabel = String(req.body.label || key.label)
  key.label = nextLabel

  if (req.body.ownerId) {
    key.ownerId = req.body.ownerId
  }

  res.json(key)
})

app.delete("/api/resources/apis/:apiId/keys/:keyId", withAuth, authorizeRoute([
  {
    action: "delete",
    resolve: async (req) => {
      const key = keyStore[String(req.params.keyId)]
      return buildApiKeyResource(
        key ?? {
          id: String(req.params.keyId),
          apiId: String(req.params.apiId),
          ownerId: req.authz?.principal.id ?? "u1",
          label: "",
        },
      )
    },
  },
]), (req, res) => {
  const keyId = String(req.params.keyId)
  if (!keyStore[keyId]) {
    return res.status(404).json({ error: "not_found" })
  }
  delete keyStore[keyId]
  res.json({ ok: true, deletedKeyId: keyId })
})

app.use((req, res) => {
  res.status(404).json({ error: "not_found" })
})

app.listen(3000, () => {
  console.log("Servidor rodando em http://localhost:3000")
  console.log("Abra http://localhost:3000")
})
