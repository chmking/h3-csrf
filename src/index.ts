import {
  CompatibilityEvent,
  createError,
  HTTPMethod,
  isMethod,
  setCookie,
  useBody,
  useCookie,
  useQuery,
} from 'h3'
import { defu } from 'defu'
import Tokens from 'csrf'
import type { CookieSerializeOptions } from 'cookie-es'

declare module 'h3' {
  interface IncomingMessage {
    csrfToken: () => string
  }
}

const PayloadMethods: HTTPMethod[] = ['PATCH', 'POST', 'PUT', 'DELETE']

export interface CookieOptions extends CookieSerializeOptions {
  name?: string
}

export interface Options {
  verifiedMethods?: Array<HTTPMethod>
  cookies?: CookieOptions
}

const defaultOptions: Options = {
  verifiedMethods: PayloadMethods,
  cookies: {
    name: '_csrf',
    path: '/',
  },
}

export function csrf(options: Options = {}) {
  const opt = defu(options, defaultOptions)

  const tokens = new Tokens()

  return async function csrf(event: CompatibilityEvent) {
    let secret = getSecret(event, opt.cookies)
    let token: string | undefined = undefined

    event.req.csrfToken = function csrfToken() {
      // Use cached token
      if (token) {
        return token
      }

      // Generate a new secret
      if (!secret) {
        secret = tokens.secretSync()
        setSecret(event, secret, opt.cookies)
      }

      // Create a new token
      token = tokens.create(secret)

      return token
    }

    // Generate a new secret
    if (!secret) {
      secret = tokens.secretSync()
      setSecret(event, secret, opt.cookies)
    }

    if (isMethod(event, opt.verifiedMethods)) {
      // Get the request CSRF value
      const value = await useValue(event)

      if (!tokens.verify(secret, value)) {
        return createError({
          statusCode: 403,
          statusMessage: 'invalid csrf token',
          data: {
            code: 'EBADCSRFTOKEN',
          },
        })
      }
    }
  }
}

function getSecret(event: CompatibilityEvent, options: CookieOptions) {
  const cookie = useCookie(event, options.name)
  return cookie
}

function setSecret(
  event: CompatibilityEvent,
  secret: string,
  options: CookieOptions
) {
  setCookie(event, options.name, secret, options)
}

async function useValue(
  event: CompatibilityEvent
): Promise<string | undefined> {
  // Check in the request body
  if (isMethod(event, ['PATCH', 'POST', 'PUT', 'DELETE'])) {
    const body = await useBody(event)
    if (body._csrf) {
      return body._csrf
    }
  }

  // Check params and headers
  return (
    (useQuery(event)._csrf as string) ||
    (event.req.headers['csrf-token'] as string) ||
    (event.req.headers['xsrf-token'] as string) ||
    (event.req.headers['x-csrf-token'] as string) ||
    (event.req.headers['x-xsrf-token'] as string)
  )
}
