import { serialize as serializeCookie } from "@otterhttp/cookie"
import { sign } from "@otterhttp/cookie-signature"
/* eslint-disable @typescript-eslint/no-unsafe-member-access */
import { assert, describe, expect, it } from "vitest"

import { COOKIE_SECRET, HEADER_KEY, TEST_TOKEN } from "./utils/constants"
import { getCookieFromRequest, getCookieFromResponse, switchSecret } from "./utils/helpers"
import { generateMocks, generateMocksWithToken, next } from "./utils/mock"

import { doubleCsrf } from "@/index"
import type { CSRFRequest, CSRFResponse, DoubleCsrfConfig } from "@/types"
import { Cookie } from "@otterhttp/request"

type CreateTestSuite = (
  name: string,
  // We will handle options for getSecret inside the test suite
  doubleCsrfOptions: DoubleCsrfConfig,
) => void

/**
 * This is an over engineered test suite to allow consistent testing for various configurations.
 * It explicitly mocks the bare-minimum Request and Response objects and middleware processing.
 * @param name - The name of the test suite.
 * @param doubleCsrfOptions - The DoubleCsrfConfig.
 */
export const createTestSuite: CreateTestSuite = (name, doubleCsrfOptions) => {
  describe(name, () => {
    // Initialise the package with the passed in test suite settings and a mock secret
    const { invalidCsrfTokenError, generateToken, validateRequest, doubleCsrfProtection } = doubleCsrf({
      ...doubleCsrfOptions,
    })

    const {
      cookieOptions: {
        name: cookieName = "__Host-otter.x-csrf-token",
        path = "/",
        secure = true,
        sameSite = "lax",
      } = {},
      errorConfig = {
        statusCode: 403,
        message: "invalid csrf token",
        code: "ERR_BAD_CSRF_TOKEN",
      },
    } = doubleCsrfOptions

    const generateMocksWithTokenInternal = async () =>
      generateMocksWithToken({
        cookieName,
        generateToken,
        validateRequest,
      })

    it("should initialize error via config options", () => {
      console.log(invalidCsrfTokenError)
      assert.equal(errorConfig.message, invalidCsrfTokenError.message)
      assert.equal(errorConfig.statusCode, invalidCsrfTokenError.statusCode)
      assert.equal(errorConfig.code, invalidCsrfTokenError.code)
    })

    describe("generateToken", () => {
      it("should attach both a token and its hash to the response and return a token", async () => {
        const { mockRequest, decodedCookieValue, setCookie } = await generateMocksWithTokenInternal()
        const cookieValue = `s:${sign(decodedCookieValue as string, COOKIE_SECRET)}`

        const expectedSetCookieValue = serializeCookie(cookieName, cookieValue as string, {
          path,
          httpOnly: true,
          secure,
          sameSite,
        })
        assert.equal(setCookie, expectedSetCookieValue)
      })

      it("should reuse a csrf token if a csrf cookie is already present, and overwrite is set to false", async () => {
        const { mockRequest, mockResponse, csrfToken, cookieValue: oldCookieValue } = await generateMocksWithTokenInternal()

        // reset the mock response to have no cookies (in reality this would just be a new instance of Response)
        mockResponse.setHeader("set-cookie", [])

        // overwrite is false by default
        const generatedToken = await generateToken(mockRequest, mockResponse)
        const newCookieValue = getCookieFromResponse(mockResponse)

        assert.equal(generatedToken, csrfToken)
        assert.equal(newCookieValue, oldCookieValue)
      })

      it("should generate a new token even if a csrf cookie is already present, if overwrite is set to true", async () => {
        const { mockRequest, mockResponse, csrfToken, cookieValue: oldCookieValue } = await generateMocksWithTokenInternal()

        // reset the mock response to have no cookies (in reality this would just be a new instance of Response)
        mockResponse.setHeader("set-cookie", [])

        const generatedToken = await generateToken(mockRequest, mockResponse, {
          overwrite: true,
        })
        const newCookieValue = getCookieFromResponse(mockResponse)

        assert.notEqual(newCookieValue, oldCookieValue)
        assert.notEqual(generatedToken, csrfToken)
      })

      it("should throw if csrf cookie is present and invalid, overwrite is false, and validateOnReuse is enabled", async () => {
        const { mockRequest, mockResponse, decodedCookieValue } = await generateMocksWithTokenInternal()
        // modify the cookie to make the token/hash pair invalid
        const cookieJar = mockRequest.cookies
        cookieJar[cookieName] = new Cookie(`${(decodedCookieValue as string).split("|")[0]}|invalid-hash`)

        await expect(
          generateToken(mockRequest, mockResponse, {
            overwrite: false,
            validateOnReuse: true,
          }),
        ).rejects.toThrow(invalidCsrfTokenError.message)

        // just an invalid value in the cookie
        cookieJar[cookieName] = new Cookie("invalid-value")

        await expect(
          generateToken(mockRequest, mockResponse, {
            overwrite: false,
            validateOnReuse: true,
          }),
        ).rejects.toThrow(invalidCsrfTokenError.message)
      })

      it("should not throw if csrf cookie is present and invalid when overwrite is false, and validateOnReuse is disabled", async () => {
        const {
          mockRequest,
          mockResponse,
          decodedCookieValue,
          cookieValue: oldCookieValue,
          csrfToken,
        } = await generateMocksWithTokenInternal()

        let generatedToken = ""
        let newCookieValue = ""

        mockResponse.setHeader("set-cookie", [])
        // modify the cookie to make the token/hash pair invalid
        const cookieJar = mockRequest.cookies
        cookieJar[cookieName] = new Cookie(`${(decodedCookieValue as string).split("|")[0]}|invalid-hash`)

        async function runGenerateToken() {
          generatedToken = await generateToken(mockRequest, mockResponse, {
            overwrite: false,
            validateOnReuse: false
          })
        }

        await expect(runGenerateToken()).resolves.not.toThrow()

        newCookieValue = getCookieFromResponse(mockResponse)
        assert.notEqual(newCookieValue, oldCookieValue)
        assert.notEqual(generatedToken, csrfToken)

        // just an invalid value in the cookie
        cookieJar[cookieName] = new Cookie("invalid-value")

        await expect(runGenerateToken()).resolves.not.toThrow()

        newCookieValue = getCookieFromResponse(mockResponse)
        assert.notEqual(newCookieValue, oldCookieValue)
        assert.notEqual(generatedToken, csrfToken)
      })
    })

    describe("validateRequest", () => {
      it("should return false when no token has been generated", async () => {
        const { mockRequest, mockResponse } = generateMocks()
        assert.isFalse(await validateRequest(mockRequest, mockResponse))
      })

      it("should return false when a token is generated but not received in request", async () => {
        const { mockRequest, mockResponse, decodedCookieValue } = await generateMocksWithTokenInternal()
        assert.equal(getCookieFromRequest(cookieName, mockRequest), decodedCookieValue)

        // Wipe token
        mockRequest.headers = {}
        assert.isFalse(await validateRequest(mockRequest, mockResponse))
      })

      it("should return false when token does not match", async () => {
        const { mockRequest, mockResponse } = await generateMocksWithTokenInternal()
        mockRequest.headers[HEADER_KEY] = TEST_TOKEN
        assert.isFalse(await validateRequest(mockRequest, mockResponse))
      })

      it("should return false when cookie is not present", async () => {
        const { mockRequest, mockResponse } = await generateMocksWithTokenInternal()
        // Wipe hash
        delete mockRequest.cookies[cookieName]
        assert.isFalse(await validateRequest(mockRequest, mockResponse))
      })
    })

    describe("doubleCsrfProtection", async () => {
      const assertProtectionToThrow = async (request: CSRFRequest, response: CSRFResponse) => {
        await expect(doubleCsrfProtection(request, response, next)).rejects.toThrow(invalidCsrfTokenError.message)
      }

      const assertProtectionToNotThrow = async (request: CSRFRequest, response: CSRFResponse) => {
        await expect(doubleCsrfProtection(request, response, next)).resolves.not.toThrow()
      }

      it("should allow requests with an ignored method", async () => {
        const { mockRequest, mockResponse } = generateMocks()
        mockRequest.method = "GET"
        await assertProtectionToNotThrow(mockRequest, mockResponse)

        // Show an invalid case
        const { mockResponse: mockResponseWithToken } = await generateMocksWithToken({
          cookieName,
          generateToken,
          validateRequest,
        })
        mockRequest.method = "POST"
        await assertProtectionToThrow(mockRequest, mockResponseWithToken)
        // Works as get
        mockRequest.method = "GET"
        await assertProtectionToNotThrow(mockRequest, mockResponseWithToken)
      })

      it("should allow a valid request", async () => {
        const { mockResponse, mockRequest } = await generateMocksWithTokenInternal()
        await assertProtectionToNotThrow(mockRequest, mockResponse)
      })

      it("should not allow request after secret rotation", async () => {
        const { mockResponse, mockRequest } = await generateMocksWithTokenInternal()
        await assertProtectionToNotThrow(mockRequest, mockResponse)
        switchSecret()
        await assertProtectionToThrow(mockRequest, mockResponse)
      })

      it("should not allow a protected request with no cookie", async () => {
        const { mockResponse, mockRequest } = await generateMocksWithTokenInternal()
        delete mockRequest.cookies[cookieName]
        await assertProtectionToThrow(mockRequest, mockResponse)
      })

      it("should not allow a protected request with no token", async () => {
        const { mockResponse, mockRequest } = await generateMocksWithTokenInternal()
        delete mockRequest.headers[HEADER_KEY]
        assert.isUndefined(mockRequest.headers[HEADER_KEY])
        await assertProtectionToThrow(mockRequest, mockResponse)
      })

      it("should not allow a protected request with a mismatching token and cookie", async () => {
        const { mockResponse, mockRequest } = await generateMocksWithTokenInternal()
        await assertProtectionToNotThrow(mockRequest, mockResponse)
        mockRequest.headers[HEADER_KEY] = TEST_TOKEN
        await assertProtectionToThrow(mockRequest, mockResponse)
      })
    })
  })
}
