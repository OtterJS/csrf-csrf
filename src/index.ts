import { createHmac, randomBytes } from "node:crypto"
import { type SerializeOptions, serialize } from "@otterhttp/cookie"
import { sign } from "@otterhttp/cookie-signature"
import { ClientError } from "@otterhttp/errors"

import type {
  CSRFRequest,
  CsrfRequestValidator,
  CsrfTokenAndHashPairValidator,
  CsrfTokenCreator,
  DoubleCsrfConfig,
  DoubleCsrfUtilities,
  GenerateCsrfTokenConfig,
  RequestMethod,
  ResolvedCSRFCookieOptions,
  Response,
  doubleCsrfProtection,
} from "./types"

function setSecretCookie(
  req: CSRFRequest,
  res: Response,
  secret: string,
  { signed, getSigningSecret, name, ...options }: ResolvedCSRFCookieOptions,
): void {
  if (!signed) {
    setCookie(res, name, secret, options)
    return
  }

  let signingSecret = getSigningSecret(req)
  if (Array.isArray(signingSecret)) signingSecret = signingSecret[0]

  const value = `s:${sign(secret, signingSecret)}`
  setCookie(res, name, value, options)
}

function setCookie(res: Response, name: string, value: string, options: SerializeOptions): void {
  const data = serialize(name, value, options)
  res.appendHeader("set-cookie", data)
}

export function doubleCsrf({
  getSecret,
  getSessionIdentifier,
  cookieOptions,
  delimiter = "|",
  size = 64,
  hmacAlgorithm = "sha256",
  ignoredMethods = ["GET", "HEAD", "OPTIONS"],
  getTokenFromRequest = (req) => {
    const header = req.headers["x-csrf-token"]
    if (typeof header !== "string") return null
    return header
  },
  errorConfig: { statusCode = 403, message = "invalid csrf token", code = "ERR_BAD_CSRF_TOKEN" } = {},
}: DoubleCsrfConfig): DoubleCsrfUtilities {
  const ignoredMethodsSet = new Set(ignoredMethods)
  const defaultCookieOptions: ResolvedCSRFCookieOptions = Object.assign({
    name: "__Host-otter.x-csrf-token",
    sameSite: "lax",
    path: "/",
    secure: true,
    httpOnly: true,
    signed: false,
  }, cookieOptions)

  const invalidCsrfTokenError = new ClientError(message, {
    statusCode: statusCode,
    code: code,
  })

  const generateTokenAndHash = (
    req: CSRFRequest,
    { overwrite, validateOnReuse }: Omit<GenerateCsrfTokenConfig, "cookieOptions">,
  ) => {
    const getSecretResult = getSecret(req)
    const possibleSecrets = Array.isArray(getSecretResult) ? getSecretResult : [getSecretResult]

    const csrfCookie = getCsrfCookieFromRequest(req)
    // If ovewrite is true, always generate a new token.
    // If overwrite is false and there is no existing token, generate a new token.
    // If overwrite is false and there is an existin token then validate the token and hash pair
    // the existing cookie and reuse it if it is valid. If it isn't valid, then either throw or
    // generate a new token based on validateOnReuse.
    if (typeof csrfCookie === "string" && !overwrite) {
      const [csrfToken, csrfTokenHash] = csrfCookie.split(delimiter)
      if (
        validateTokenAndHashPair(req, {
          incomingToken: csrfToken,
          incomingHash: csrfTokenHash,
          possibleSecrets,
        })
      ) {
        // If the pair is valid, reuse it
        return { csrfToken, csrfTokenHash }
      }

      if (validateOnReuse) {
        // If the pair is invalid, but we want to validate on generation, throw an error
        // only if the option is set
        throw invalidCsrfTokenError
      }
    }
    // otherwise, generate a completely new token
    const csrfToken = randomBytes(size).toString("hex")
    // the 'newest' or preferred secret is the first one in the array
    const secret = possibleSecrets[0]
    const csrfTokenHash = createHmac(hmacAlgorithm, secret)
      .update(`${getSessionIdentifier(req)}${csrfToken}`)
      .digest("hex")

    return { csrfToken, csrfTokenHash }
  }

  // Generates a token, sets the cookie on the response and returns the token.
  // This should be used in routes or middleware to provide users with a token.
  // The value returned from this should ONLY be sent to the client via a response payload.
  // Do NOT send the csrfToken as a cookie, embed it in your HTML response, or as JSON.
  const generateToken: CsrfTokenCreator = (
    req: CSRFRequest,
    res: Response,
    { cookieOptions = defaultCookieOptions, overwrite = false, validateOnReuse = true } = {},
  ) => {
    const { csrfToken, csrfTokenHash } = generateTokenAndHash(req, {
      overwrite,
      validateOnReuse,
    })
    const cookieContent = `${csrfToken}${delimiter}${csrfTokenHash}`

    setSecretCookie(req, res, cookieContent,  Object.assign({}, defaultCookieOptions, cookieOptions))

    return csrfToken
  }

  const getCsrfCookieFromRequest = defaultCookieOptions.signed
    ? (req: CSRFRequest) => req.signedCookies?.[defaultCookieOptions.name]
    : (req: CSRFRequest) => req.cookies?.[defaultCookieOptions.name]

  // given a secret array, iterates over it and checks whether one of the secrets makes the token and hash pair valid
  const validateTokenAndHashPair: CsrfTokenAndHashPairValidator = (
    req,
    { incomingHash, incomingToken, possibleSecrets },
  ) => {
    if (typeof incomingToken !== "string" || typeof incomingHash !== "string") return false

    for (const secret of possibleSecrets) {
      const expectedHash = createHmac(hmacAlgorithm, secret)
        .update(`${getSessionIdentifier(req)}${incomingToken}`)
        .digest("hex")
      if (incomingHash === expectedHash) return true
    }

    return false
  }

  const validateRequest: CsrfRequestValidator = (req) => {
    // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-member-access
    const csrfCookie = getCsrfCookieFromRequest(req)
    if (typeof csrfCookie !== "string") return false

    // cookie has the form {token}{delimiter}{hash}
    const [csrfTokenFromCookie, csrfTokenHash] = csrfCookie.split(delimiter)

    // csrf token from the request
    const csrfTokenFromRequest = getTokenFromRequest(req) as string

    const getSecretResult = getSecret(req)
    const possibleSecrets = Array.isArray(getSecretResult) ? getSecretResult : [getSecretResult]

    return (
      csrfTokenFromCookie === csrfTokenFromRequest &&
      validateTokenAndHashPair(req, {
        incomingToken: csrfTokenFromRequest,
        incomingHash: csrfTokenHash,
        possibleSecrets,
      })
    )
  }

  const doubleCsrfProtection: doubleCsrfProtection = (req, res, next) => {
    if (ignoredMethodsSet.has(req.method as RequestMethod)) {
      next()
    } else if (validateRequest(req)) {
      next()
    } else {
      throw invalidCsrfTokenError
    }
  }

  return {
    invalidCsrfTokenError,
    generateToken,
    validateRequest,
    doubleCsrfProtection,
  }
}

export * from "./types"
