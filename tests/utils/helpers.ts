import type { CSRFRequest, CSRFResponse } from "@/types"

const SECRET_1 = "secrets must be unique and must not"
const SECRET_2 = "be used elsewhere, nor be sentences"

const MULTIPLE_SECRETS_1 = ["secret1", "secret2"]
const MULTIPLE_SECRETS_2 = ["secret3", "secret4"]

// We do this to create a closure where we can externally switch the boolean value
export const { getSingleSecret, getMultipleSecrets, switchSecret } = (() => {
  let secretSwitcher = false

  return {
    getSingleSecret: () => (secretSwitcher ? SECRET_1 : SECRET_2),
    getMultipleSecrets: () => (secretSwitcher ? MULTIPLE_SECRETS_1 : MULTIPLE_SECRETS_2),
    switchSecret: () => {
      secretSwitcher = !secretSwitcher
    },
  }
})()

/**
 * Parses the response 'Set-Cookie' header.
 * @param res The response object
 * @returns The set-cookie header string and the cookie value containing both the csrf token and its hash
 */
export const getCookieValueFromResponse = (res: CSRFResponse) => {
  const setCookie = res.getHeader("set-cookie") as string | string[]
  const setCookieString: string = Array.isArray(setCookie) ? setCookie[0] : setCookie
  const cookieValue = setCookieString.substring(setCookieString.indexOf("=") + 1, setCookieString.indexOf(";"))

  return {
    setCookie: setCookieString,
    cookieValue,
  }
}

// Returns the cookie value from the request, accommodate signed and unsigned.
export const getCookieFromRequest = (cookieName: string, req: CSRFRequest) =>
  // eslint-disable-next-line @typescript-eslint/no-unsafe-return, @typescript-eslint/no-unsafe-member-access
  req.cookies[cookieName].value

// as of now, we only have one cookie, so we can just return the first one
export const getCookieFromResponse = (res: CSRFResponse) => {
  const setCookie = res.getHeader("set-cookie") as string | string[]
  const setCookieString: string = Array.isArray(setCookie) ? setCookie[0] : setCookie
  const cookieValue = setCookieString.substring(setCookieString.indexOf("=") + 1, setCookieString.indexOf(";"))

  return cookieValue
}

/**
 * Given a request object, it will attach to it the CSRF header and cookie values from a given response object.
 * @param mockRequest The mock request object
 * @param mockResponse The mock response object
 * @param bodyResponseToken The CSRF token from the response body
 * @param cookieName The name of the CSRF cookie
 * @param headerKey The name of the CSRF header
 * @returns The request object with the CSRF header and cookie values attached
 */
export const attachResponseValuesToRequest = ({
  request,
  response,
  bodyResponseToken,
  cookieName,
  headerKey,
}: {
  request: CSRFRequest
  response: CSRFResponse
  bodyResponseToken: string
  cookieName: string
  headerKey: string
}) => {
  const { cookieValue } = getCookieValueFromResponse(response)

  // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access
  request.headers.cookie = `${cookieName}=${cookieValue};`
  // @ts-expect-error
  request._cookies = null

  request.headers[headerKey] = bodyResponseToken
}

export const legacySessionIdentifier = () => "f5d7e7d1-a0dd-cf55-c0bb-5aa5aabe441f"
