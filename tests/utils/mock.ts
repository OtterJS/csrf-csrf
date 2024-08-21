import { IncomingMessage, ServerResponse } from "node:http"
import { parse } from "@otterhttp/cookie"
import { cookieParser, signedCookie } from "@tinyhttp/cookie-parser"
import { assert } from "vitest"

import { COOKIE_SECRET, HEADER_KEY } from "./constants.js"
import { getCookieFromRequest, getCookieValueFromResponse } from "./helpers.js"
import type { Request, Response } from "./mock-types"

import type { CsrfRequestValidator, CsrfTokenCreator } from "@/types.js"

// Create some request and response mocks
export const generateMocks = () => {
  const mockRequest: Request = Object.assign(new IncomingMessage(undefined as any), {
    cookies: {},
    signedCookies: {},
  })

  const mockResponse: Response = new ServerResponse(mockRequest)

  return {
    mockRequest,
    mockResponse,
  }
}

export const next = () => undefined

export const cookieParserMiddleware = cookieParser(COOKIE_SECRET)

export type GenerateMocksWithTokenOptions = {
  cookieName: string
  signed: boolean
  generateToken: CsrfTokenCreator
  validateRequest: CsrfRequestValidator
}

// Generate the request and response mocks.
// Set them up as if they have been pre-processed in a valid state.
export const generateMocksWithToken = ({
  cookieName,
  signed,
  generateToken,
  validateRequest,
}: GenerateMocksWithTokenOptions) => {
  const { mockRequest, mockResponse } = generateMocks()

  const csrfToken = generateToken(mockRequest, mockResponse)
  const { setCookie, cookieValue } = getCookieValueFromResponse(mockResponse)
  mockRequest.headers.cookie = `${cookieName}=${cookieValue};`
  const decodedCookieValue = signed
    ? signedCookie(parse(mockRequest.headers.cookie)[cookieName], COOKIE_SECRET)
    : // signedCookie already decodes the value, but we need it if it's not signed.
      decodeURIComponent(cookieValue)
  // Have to delete the cookies object otherwise cookieParser will skip its parsing.
  // @ts-expect-error
  mockRequest.cookies = undefined
  cookieParserMiddleware(mockRequest, mockResponse, next)
  assert.equal(getCookieFromRequest(cookieName, signed, mockRequest), decodedCookieValue)

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
