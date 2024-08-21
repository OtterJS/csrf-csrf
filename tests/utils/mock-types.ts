import type { IncomingMessage, ServerResponse } from "node:http"

export type Request = IncomingMessage & {
  cookies: Record<string, unknown>
  signedCookies: Record<string, unknown>
}

export type Response = ServerResponse
