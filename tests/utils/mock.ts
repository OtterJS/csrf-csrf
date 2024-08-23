import { ServerResponse } from "node:http"
import type { Socket } from "node:net"
import { type SerializeOptions, parse, serialize } from "@otterhttp/cookie"
import { sign, unsign } from "@otterhttp/cookie-signature"
import { Request } from "@otterhttp/request"
import { assert } from "vitest"

import { COOKIE_SECRET, HEADER_KEY } from "./constants.js"
import { getCookieFromRequest, getCookieValueFromResponse } from "./helpers.js"

import type { CSRFRequest, CSRFResponse, CsrfRequestValidator, CsrfTokenCreator } from "@/types.js"

// Create some request and response mocks
export const generateMocks = () => {
  const mockRequest: CSRFRequest = Object.assign(new Request(undefined as unknown as Socket), {
    appSettings: {
      cookieParsing: {
        encodedCookieMatcher: (value: string) => decodeURIComponent(value).startsWith("s:"),
        cookieDecoder: (value: string) => {
          const result = unsign(decodeURIComponent(value).slice(2), COOKIE_SECRET)
          if (result === false) throw new Error("Failed to parse cookie")
          return result
        },
      },
    },
  })

  const mockResponse: CSRFResponse = Object.assign(new ServerResponse(mockRequest), {
    cookie: function (
      this: ServerResponse<CSRFRequest>,
      name: string,
      value: string,
      options?: SerializeOptions,
    ): unknown {
      const resolvedOptions = Object.assign(
        {},
        {
          encode: (value: string) => encodeURIComponent(`s:${sign(value, COOKIE_SECRET)}`),
        },
        options,
      )
      this.appendHeader("set-cookie", serialize(name, value, resolvedOptions))
      return this
    },
  })

  return {
    mockRequest,
    mockResponse,
  }
}

export const next = () => undefined

export type GenerateMocksWithTokenOptions = {
  cookieName: string
  generateToken: CsrfTokenCreator
  validateRequest: CsrfRequestValidator
}

// Generate the request and response mocks.
// Set them up as if they have been pre-processed in a valid state.
export const generateMocksWithToken = ({
  cookieName,
  generateToken,
  validateRequest,
}: GenerateMocksWithTokenOptions) => {
  const { mockRequest, mockResponse } = generateMocks()

  const csrfToken = generateToken(mockRequest, mockResponse)
  const { setCookie, cookieValue } = getCookieValueFromResponse(mockResponse)
  mockRequest.headers.cookie = `${cookieName}=${cookieValue};`

  // @ts-expect-error
  mockRequest._cookies = null
  const decodedCookieValue = mockRequest.cookies[cookieName].value
  assert.equal(getCookieFromRequest(cookieName, mockRequest), decodedCookieValue)

  mockRequest.headers[HEADER_KEY] = csrfToken

  // Once a token has been generated, the request should be setup as valid
  assert.isTrue(validateRequest(mockRequest))
  return {
    csrfToken,
    cookieValue,
    decodedCookieValue,
    mockRequest,
    mockResponse,
    setCookie,
  }
}
