import { App } from "@otterhttp/app"
import { sign, unsign } from "@otterhttp/cookie-signature"
import { CookieAgent } from "http-cookie-agent/undici"
import { CookieJar } from "tough-cookie"
import { expect, it, onTestFinished } from "vitest"

import { makeFetch } from "./utils/make-fetch"

import { doubleCsrf } from "@/index"

function getCookieAgent() {
  const jar = new CookieJar()
  const agent = new CookieAgent({ cookies: { jar } })
  return { jar, agent }
}

it("should behave appropriately", async () => {
  const app = new App()

  const { doubleCsrfProtection, generateToken } = doubleCsrf({
    cookieOptions: {
      name: "x-csrf-token",
      secure: false,
    },
    getSecret: () => "very_secret_secret",
    getSessionIdentifier: (req) => req.headers.session as string,
  })

  app.route("/csrf-token").get(async (req, res) => {
    res.json({ token: await generateToken(req, res) })
  })

  app
    .route("/protected")
    .post(doubleCsrfProtection)
    .post(async (req, res) => {
      res.end()
    })

  const server = app.listen()
  onTestFinished(() => void server.close())
  const fetch = makeFetch(server)
  const { agent } = getCookieAgent()

  const tokenResponse = await fetch("/csrf-token", { dispatcher: agent, headers: { session: "foobar" } })
  expect(tokenResponse.status).toBe(200)
  const { token }: { token: string } = await tokenResponse.json()

  const goodPostResponse = await fetch("/protected", {
    method: "POST",
    headers: { "x-csrf-token": token, session: "foobar" },
    dispatcher: agent,
  })
  expect(goodPostResponse.status).toBe(200)

  const badPostResponse = await fetch("/protected", {
    method: "POST",
    headers: { session: "foobar" },
  })
  expect(badPostResponse.status).toBe(403)
})

it("should behave appropriately using App-level cookie signing", async () => {
  const app = new App({
    settings: {
      setCookieOptions: {
        sign: (value) => `s:${sign(value, "other_secret_secret")}`,
      },
      cookieParsing: {
        cookieUnsigner: (signedValue) => {
          const result = unsign(signedValue.slice(2), "other_secret_secret")
          if (result === false) throw new Error()
          return result
        },
        signedCookieMatcher: (value) => value.startsWith("s:"),
      },
    },
  })

  const { doubleCsrfProtection, generateToken } = doubleCsrf({
    cookieOptions: {
      name: "x-csrf-token",
      secure: false,
    },
    getSecret: () => "very_secret_secret",
    getSessionIdentifier: (req) => req.headers.session as string,
  })

  app.route("/csrf-token").get(async (req, res) => {
    res.json({ token: await generateToken(req, res) })
  })

  app
    .route("/protected")
    .post(doubleCsrfProtection)
    .post(async (req, res) => {
      res.end()
    })

  const server = app.listen()
  onTestFinished(() => void server.close())
  const fetch = makeFetch(server)
  const { agent } = getCookieAgent()

  const tokenResponse = await fetch("/csrf-token", { dispatcher: agent, headers: { session: "foobar" } })
  expect(tokenResponse.status).toBe(200)
  const { token }: { token: string } = await tokenResponse.json()

  const goodPostResponse = await fetch("/protected", {
    method: "POST",
    headers: { "x-csrf-token": token, session: "foobar" },
    dispatcher: agent,
  })
  expect(goodPostResponse.status).toBe(200)

  const badPostResponse = await fetch("/protected", {
    method: "POST",
    headers: { session: "foobar" },
  })
  expect(badPostResponse.status).toBe(403)
})

it("should behave appropriately using csrf-csrf-level cookie signing", async () => {
  const app = new App()

  const { doubleCsrfProtection, generateToken } = doubleCsrf({
    cookieOptions: {
      name: "x-csrf-token",
      secure: false,
      sign: (value) => `s:${sign(value, "other_secret_secret")}`,
      unsign: (signedValue) => {
        const result = unsign(signedValue.slice(2), "other_secret_secret")
        if (result === false) throw new Error()
        return result
      },
    },
    getSecret: () => "very_secret_secret",
    getSessionIdentifier: (req) => req.headers.session as string,
  })

  app.route("/csrf-token").get(async (req, res) => {
    res.json({ token: await generateToken(req, res) })
  })

  app
    .route("/protected")
    .post(doubleCsrfProtection)
    .post(async (req, res) => {
      res.end()
    })

  const server = app.listen()
  onTestFinished(() => void server.close())
  const fetch = makeFetch(server)
  const { agent } = getCookieAgent()

  const tokenResponse = await fetch("/csrf-token", { dispatcher: agent, headers: { session: "foobar" } })
  expect(tokenResponse.status).toBe(200)
  const { token }: { token: string } = await tokenResponse.json()

  const goodPostResponse = await fetch("/protected", {
    method: "POST",
    headers: { "x-csrf-token": token, session: "foobar" },
    dispatcher: agent,
  })
  expect(goodPostResponse.status).toBe(200)

  const badPostResponse = await fetch("/protected", {
    method: "POST",
    headers: { session: "foobar" },
  })
  expect(badPostResponse.status).toBe(403)
})
