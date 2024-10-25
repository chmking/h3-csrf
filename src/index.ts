import {
  H3Event,
  createError,
  isMethod,
  setCookie,
  readBody,
  getCookie,
  getQuery,
} from 'h3'
import { createDefu } from 'defu'
import Tokens from 'csrf'
import type { CookieSerializeOptions } from 'cookie-es'

declare module 'http' {
  interface IncomingMessage {
    csrfToken: () => string
  }
}

declare module 'cookie-es' {
  interface CookieSerializeOptions {
    name?: string
  }
}

type HTTPMethod =
  | 'GET'
  | 'HEAD'
  | 'POST'
  | 'PUT'
  | 'DELETE'
  | 'CONNECT'
  | 'OPTIONS'
  | 'TRACE'
  | 'PATCH'

const PayloadMethods: HTTPMethod[] = ['PATCH', 'POST', 'PUT', 'DELETE']

export interface Options {
  verifiedMethods?: Array<HTTPMethod>
  cookie?: CookieSerializeOptions
}

const defaultOptions: Options = {
  verifiedMethods: PayloadMethods,
  cookie: {
    name: '_csrf',
    path: '/',
  },
}

export function csrf(options: Options = {}) {
  const defu = createDefu((obj, key, value) => {
    if (key === 'verifiedMethods') {
      obj[key] = Array.isArray(value) ? value : obj[key]
      return true
    }
  })
  const opt = defu(options, defaultOptions)

  const tokens = new Tokens()

  return async function csrf(event: H3Event) {
    let secret = getSecret(event, opt.cookie)
    let token: string | undefined = undefined

    event.req.csrfToken = function csrfToken() {
      // Use cached token
      if (token) {
        return token
      }

      // Generate a new secret
      if (!secret) {
        secret = tokens.secretSync()
        setSecret(event, secret, opt.cookie)
      }

      // Create a new token
      token = tokens.create(secret)

      return token
    }

    // Generate a new secret
    if (!secret) {
      secret = tokens.secretSync()
      setSecret(event, secret, opt.cookie)
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

function getSecret(event: H3Event, options: CookieSerializeOptions) {
  const cookie = getCookie(event, options.name)
  return cookie
}

function setSecret(
  event: H3Event,
  secret: string,
  options: CookieSerializeOptions
) {
  setCookie(event, options.name, secret, options)
}

async function useValue(event: H3Event): Promise<string | undefined> {
  // Check in the request body
  if (isMethod(event, ['PATCH', 'POST', 'PUT', 'DELETE'])) {
    const body = await readBody(event)
    if (body?._csrf) {
      return body._csrf
    }
  }

  // Check params and headers
  return (
    (getQuery(event)._csrf as string) ||
    (event.req.headers['csrf-token'] as string) ||
    (event.req.headers['xsrf-token'] as string) ||
    (event.req.headers['x-csrf-token'] as string) ||
    (event.req.headers['x-xsrf-token'] as string)
  )
}
