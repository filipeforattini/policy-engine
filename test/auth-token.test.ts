import { test } from "node:test"
import assert from "node:assert/strict"
import request from "supertest"
import { app } from "../src/server"

test("POST /auth/token returns 401 invalid_credentials for unknown userId", async () => {
  const res = await request(app)
    .post("/auth/token")
    .send({ userId: "ghost" })
    .set("content-type", "application/json")
  assert.equal(res.status, 401)
  assert.deepEqual(res.body, { error: "invalid_credentials" })
})

test("POST /auth/token returns 401 invalid_credentials when userId missing", async () => {
  const res = await request(app)
    .post("/auth/token")
    .send({})
    .set("content-type", "application/json")
  assert.equal(res.status, 401)
  assert.deepEqual(res.body, { error: "invalid_credentials" })
})

test("POST /auth/token does not enumerate: unknown user response identical to missing-userId response", async () => {
  const unknown = await request(app)
    .post("/auth/token")
    .send({ userId: "ghost" })
    .set("content-type", "application/json")
  const missing = await request(app)
    .post("/auth/token")
    .send({})
    .set("content-type", "application/json")

  assert.equal(unknown.status, missing.status)
  assert.deepEqual(unknown.body, missing.body)
})

test("POST /auth/token still issues a token for known user (regression)", async () => {
  const res = await request(app)
    .post("/auth/token")
    .send({ userId: "u1" })
    .set("content-type", "application/json")
  assert.equal(res.status, 200)
  assert.equal(typeof res.body.accessToken, "string")
  assert.equal(res.body.tokenType, "Bearer")
  assert.equal(res.body.user.id, "u1")
})
