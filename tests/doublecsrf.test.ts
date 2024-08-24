import { doubleCsrf } from "@/index"
import type { DoubleCsrfConfig } from "@/types"
/* eslint-disable @typescript-eslint/ban-ts-comment */
import { assert, describe, it } from "vitest"
import { createTestSuite } from "./testsuite"
import { COOKIE_SECRET, HEADER_KEY } from "./utils/constants"
import {
  attachResponseValuesToRequest,
  getMultipleSecrets,
  getSingleSecret,
  legacySessionIdentifier,
} from "./utils/helpers.js"
import { generateMocks, generateMocksWithToken } from "./utils/mock.js"

createTestSuite("csrf-csrf single secret", {
  getSecret: getSingleSecret,
  getSessionIdentifier: legacySessionIdentifier,
})

createTestSuite("csrf-csrf custom options, single secret", {
  getSecret: getSingleSecret,
  getSessionIdentifier: legacySessionIdentifier,
  cookieOptions: {
    name: "__Host.test-the-thing.token",
    sameSite: "strict",
  },
  size: 128,
  delimiter: "~",
  hmacAlgorithm: "sha512",
})

createTestSuite("csrf-csrf multiple secrets", {
  getSecret: getMultipleSecrets,
  getSessionIdentifier: legacySessionIdentifier,
})

createTestSuite("csrf-csrf custom options, multiple secrets", {
  getSecret: getMultipleSecrets,
  getSessionIdentifier: legacySessionIdentifier,
  cookieOptions: {
    name: "__Host.test-the-thing.token",
    sameSite: "strict",
  },
  size: 128,
  errorConfig: {
    statusCode: 401,
    message: "GO AWAY",
    code: "FAKE",
  },
})

describe("csrf-csrf token-rotation", () => {
  // Initialise the package with the passed in test suite settings and a mock secret
  const doubleCsrfOptions: Omit<DoubleCsrfConfig, "getSecret" | "getSessionIdentifier"> = {}

  const {
    cookieOptions: { name: cookieName = "__Host-otter.x-csrf-token" } = {},
  } = doubleCsrfOptions

  const SECRET1 = "secret1"
  const SECRET2 = "secret2"

  const generateMocksWithMultipleSecrets = async (secrets: string[] | string) => {
    const { generateToken, validateRequest } = doubleCsrf({
      ...doubleCsrfOptions,
      getSecret: () => secrets,
      getSessionIdentifier: () => SECRET1,
    })

    return {
      ...await generateMocksWithToken({
        cookieName,
        generateToken,
        validateRequest,
      }),
      validateRequest,
      generateToken,
    }
  }

  describe("validating requests with combination of different secret/s", async () => {
    // Generate request --> CSRF token with secret1
    // We will then match a request with token and secret1 with other combinations of secrets
    const { mockRequest, mockResponse, validateRequest } = await generateMocksWithMultipleSecrets(SECRET1)
    assert.isTrue(await validateRequest(mockRequest, mockResponse))

    it("should be valid with 1 matching secret", async () => {
      const { validateRequest } = await generateMocksWithMultipleSecrets(SECRET1)
      assert.isTrue(await validateRequest(mockRequest, mockResponse))
    })

    it("should be valid with 1/1 matching secret in array", async () => {
      const { validateRequest } = await generateMocksWithMultipleSecrets([SECRET1])
      assert.isTrue(await validateRequest(mockRequest, mockResponse))
    })

    it("should be valid with 1/2 matching secrets in array, first secret matches", async () => {
      const { validateRequest } = await generateMocksWithMultipleSecrets([SECRET1, SECRET2])
      assert.isTrue(await validateRequest(mockRequest, mockResponse))
    })

    it("should be valid with 1/2 matching secrets in array, second secret matches", async () => {
      const { validateRequest } = await generateMocksWithMultipleSecrets([SECRET2, SECRET1])
      assert.isTrue(await validateRequest(mockRequest, mockResponse))
    })

    it("should be invalid with 0/1 matching secret in array", async () => {
      const { validateRequest } = await generateMocksWithMultipleSecrets([SECRET2])
      assert.isFalse(await validateRequest(mockRequest, mockResponse))
    })

    it("should be invalid with 0/2 matching secrets in array", async () => {
      const { validateRequest } = await generateMocksWithMultipleSecrets(SECRET2)
      assert.isFalse(await validateRequest(mockRequest, mockResponse))
    })

    it("should be invalid with 0/3 matching secrets in array", async () => {
      const { validateRequest } = await generateMocksWithMultipleSecrets(["invalid0", "invalid1", "invalid2"])
      assert.isFalse(await validateRequest(mockRequest, mockResponse))
    })
  })

  describe("should generate tokens correctly, simulating token rotations", async () => {
    const getEmptyResponse = () => {
      const { mockResponse } = generateMocks()
      return mockResponse
    }

    const { validateRequest: validateRequestWithSecret1 } = await generateMocksWithMultipleSecrets(SECRET1)

    const { validateRequest: validateRequestWithSecret2 } = await generateMocksWithMultipleSecrets(SECRET2)

    const { generateToken: generateTokenWithSecret1And2 } = await generateMocksWithMultipleSecrets([SECRET1, SECRET2])

    const { generateToken: generateTokenWithSecret2And1 } = await generateMocksWithMultipleSecrets([SECRET2, SECRET1])

    it("should reuse existing token on request with SECRET1, while current is [SECRET1, SECRET2]", async () => {
      const { mockRequest } = await generateMocksWithMultipleSecrets(SECRET1)
      const mockResponse = getEmptyResponse()

      const token = await generateTokenWithSecret1And2(mockRequest, mockResponse)
      attachResponseValuesToRequest({
        request: mockRequest,
        response: mockResponse,
        headerKey: HEADER_KEY,
        cookieName,
        bodyResponseToken: token,
      })

      assert.isTrue(await validateRequestWithSecret1(mockRequest, mockResponse))
      assert.isFalse(await validateRequestWithSecret2(mockRequest, mockResponse))
    })

    it("should reuse existing token on request with SECRET1, while current is [SECRET2, SECRET1]", async () => {
      const { mockRequest } = await generateMocksWithMultipleSecrets(SECRET1)
      const mockResponse = getEmptyResponse()

      const token = await generateTokenWithSecret2And1(mockRequest, mockResponse)
      attachResponseValuesToRequest({
        request: mockRequest,
        response: mockResponse,
        headerKey: HEADER_KEY,
        cookieName,
        bodyResponseToken: token,
      })

      assert.isTrue(await validateRequestWithSecret1(mockRequest, mockResponse))
      assert.isFalse(await validateRequestWithSecret2(mockRequest, mockResponse))
    })

    it("should generate new token (with secret 1) on request with SECRET2, while current is [SECRET1, SECRET2], if overwrite is true", async () => {
      const { mockRequest } = await generateMocksWithMultipleSecrets(SECRET2)

      const mockResponse = getEmptyResponse()

      const token = await generateTokenWithSecret1And2(mockRequest, mockResponse, {
        overwrite: true,
      })

      attachResponseValuesToRequest({
        request: mockRequest,
        response: mockResponse,
        headerKey: HEADER_KEY,
        cookieName,
        bodyResponseToken: token,
      })

      assert.isFalse(await validateRequestWithSecret2(mockRequest, mockResponse))
      assert.isTrue(await validateRequestWithSecret1(mockRequest, mockResponse))
    })

    it("should generate new token (with secret 2) on request with SECRET2, while current is [SECRET2, SECRET1], if overwrite is true", async () => {
      const { mockRequest } = await generateMocksWithMultipleSecrets(SECRET2)

      const mockResponse = getEmptyResponse()

      const token = await generateTokenWithSecret2And1(mockRequest, mockResponse, {
        overwrite: true,
      })

      attachResponseValuesToRequest({
        request: mockRequest,
        response: mockResponse,
        headerKey: HEADER_KEY,
        cookieName,
        bodyResponseToken: token,
      })

      assert.isTrue(await validateRequestWithSecret2(mockRequest, mockResponse))
      assert.isFalse(await validateRequestWithSecret1(mockRequest, mockResponse))
    })
  })
})
