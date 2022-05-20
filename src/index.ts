import {
  CompatibilityEvent,
  createError,
  HTTPMethod,
  isMethod,
  setCookie,
  useBody,
  useCookie,
  useQuery,
} from "h3";
import { defu } from "defu";
import Tokens from "csrf";

declare module "h3" {
  interface IncomingMessage {
    csrfToken: () => string;
  }
}

const PayloadMethods: HTTPMethod[] = ["PATCH", "POST", "PUT", "DELETE"];

export interface Options {
  verifiedMethods?: Array<HTTPMethod>;
}

const defaultOptions: Options = {
  verifiedMethods: PayloadMethods,
};

export function csurf(options: Options = {}) {
  const opt = defu(options, defaultOptions);

  const tokens = new Tokens();

  return async function csrf(event: CompatibilityEvent) {
    var secret = getSecret(event);
    var token: string | undefined = undefined;

    event.req.csrfToken = function csrfToken() {
      // Use cached token
      if (token) {
        return token;
      }

      // Generate a new secret
      if (!secret) {
        secret = tokens.secretSync();
        setSecret(event, secret);
      }

      // Create a new token
      token = tokens.create(secret);

      return token;
    };

    // Generate a new secret
    if (!secret) {
      secret = tokens.secretSync();
      setSecret(event, secret);
    }

    if (isMethod(event, opt.verifiedMethods)) {
      // Get the request CSRF value
      const value = await useValue(event);

      if (!tokens.verify(secret, value)) {
        return createError({
          statusCode: 403,
          statusMessage: "invalid csrf token",
          data: {
            code: "EBADCSRFTOKEN",
          },
        });
      }
    }
  };
}

function getSecret(event: CompatibilityEvent) {
  const cookie = useCookie(event, "_csrf");
  return cookie;
}

function setSecret(event: CompatibilityEvent, secret: string) {
  setCookie(event, "_csrf", secret);
}

async function useValue(
  event: CompatibilityEvent
): Promise<string | undefined> {
  // Check in the request body
  if (isMethod(event, ["PATCH", "POST", "PUT", "DELETE"])) {
    const body = await useBody(event);
    if (body._csrf) {
      return body._csrf;
    }
  }

  // Check params and headers
  return (
    (useQuery(event)._csrf as string) ||
    (event.req.headers["csrf-token"] as string) ||
    (event.req.headers["xsrf-token"] as string) ||
    (event.req.headers["x-csrf-token"] as string) ||
    (event.req.headers["x-xsrf-token"] as string)
  );
}
