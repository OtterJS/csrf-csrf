import type { IncomingMessage, Server, ServerResponse } from "node:http"

type FetchInit = Parameters<typeof fetch>[1]

export function makeFetch<
  Req extends typeof IncomingMessage = typeof IncomingMessage,
  Res extends typeof ServerResponse<InstanceType<Req>> = typeof ServerResponse<InstanceType<Req>>,
  // @ts-expect-error
>(server: Server<Req, Res>) {
  const address = server.address()
  if (address == null) throw new Error("Somehow, the server is not listening")
  if (typeof address === "string") throw new Error("Listening on a unix socket is not supported")

  return async (path: string, init?: FetchInit & { dispatcher?: unknown }) =>
    await fetch(new URL(path, `http://localhost:${address.port}`), init)
}
