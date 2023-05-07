import type { CookieParseOptions, CookieSerializeOptions } from "cookie";
import { parse, serialize } from "cookie";
import jose from "jose";

import { warnOnce } from "./warnings";

export type { CookieParseOptions, CookieSerializeOptions };

export interface CookieSecureOptions {
  /**
   * An array of secrets that may be used to sign/unsign the value of a cookie.
   *
   * The array makes it easy to rotate secrets. New secrets should be added to
   * the beginning of the array. `cookie.serialize()` will always use the first
   * value in the array, but `cookie.parse()` may use any of them so that
   * cookies that were signed with older secrets still work.
   */
  secrets?: string[];
  encrypt?: boolean;
}

export type CookieOptions = CookieParseOptions &
  CookieSerializeOptions &
  CookieSecureOptions;

/**
 * A HTTP cookie.
 *
 * A Cookie is a logical container for metadata about a HTTP cookie; its name
 * and options. But it doesn't contain a value. Instead, it has `parse()` and
 * `serialize()` methods that allow a single instance to be reused for
 * parsing/encoding multiple different values.
 *
 * @see https://remix.run/utils/cookies#cookie-api
 */
export interface Cookie {
  /**
   * The name of the cookie, used in the `Cookie` and `Set-Cookie` headers.
   */
  readonly name: string;

  /**
   * True if this cookie uses one or more secrets for verification.
   */
  readonly isSigned: boolean;

  /**
   * The Date this cookie expires.
   *
   * Note: This is calculated at access time using `maxAge` when no `expires`
   * option is provided to `createCookie()`.
   */
  readonly expires?: Date;

  /**
   * Parses a raw `Cookie` header and returns the value of this cookie or
   * `null` if it's not present.
   */
  parse(
    cookieHeader: string | null,
    options?: CookieParseOptions
  ): Promise<any>;

  /**
   * Serializes the given value to a string and returns the `Set-Cookie`
   * header.
   */
  serialize(value: any, options?: CookieSerializeOptions): Promise<string>;
}

export type CreateCookieFunction = (
  name: string,
  cookieOptions?: CookieOptions
) => Cookie;

/**
 * Creates a logical container for managing a browser cookie from the server.
 *
 * @see https://remix.run/utils/cookies#createcookie
 */
export const createCookieFactory =
  (): CreateCookieFunction =>
  (name, cookieOptions = {}) => {
    let {
      secrets = [],
      encrypt = false,
      ...options
    } = {
      path: "/",
      sameSite: "lax" as const,
      ...cookieOptions,
    };

    warnOnceAboutExpiresCookie(name, options.expires);

    return {
      get name() {
        return name;
      },
      get isSigned() {
        return secrets.length > 0;
      },
      get expires() {
        // Max-Age takes precedence over Expires
        return typeof options.maxAge !== "undefined"
          ? new Date(Date.now() + options.maxAge * 1000)
          : options.expires;
      },
      async parse(cookieHeader, parseOptions) {
        if (!cookieHeader) return null;
        let cookies = parse(cookieHeader, { ...options, ...parseOptions });
        return name in cookies
          ? cookies[name] === ""
            ? ""
            : await decodeCookieValue(cookies[name], secrets, encrypt)
          : null;
      },
      async serialize(value, serializeOptions) {
        return serialize(
          name,
          value === "" ? "" : await encodeCookieValue(value, secrets, encrypt),
          {
            ...options,
            ...serializeOptions,
          }
        );
      },
    };
  };

export type IsCookieFunction = (object: any) => object is Cookie;

/**
 * Returns true if an object is a Remix cookie container.
 *
 * @see https://remix.run/utils/cookies#iscookie
 */
export const isCookie: IsCookieFunction = (object): object is Cookie => {
  return (
    object != null &&
    typeof object.name === "string" &&
    typeof object.isSigned === "boolean" &&
    typeof object.parse === "function" &&
    typeof object.serialize === "function"
  );
};

async function encodeCookieValue(
  value: any,
  secrets: string[],
  encrypt?: boolean
): Promise<string> {
  let encoded;

  if (secrets.length > 0) {
    if (encrypt) {
      encoded = await new jose.EncryptJWT(value)
        .setProtectedHeader({ alg: "PBES2-HS512+A256KW", enc: "A256GCM" })
        .setIssuedAt()
        .encrypt(new TextEncoder().encode(secrets[0]));
    } else {
      encoded = await new jose.SignJWT(value)
        .setProtectedHeader({ alg: "PBES2-HS512+A256KW", enc: "A256GCM" })
        .setIssuedAt()
        .sign(new TextEncoder().encode(secrets[0]));
    }
  } else {
    encoded = new jose.UnsecuredJWT(value).setIssuedAt().encode();
  }

  return encoded;
}

async function decodeCookieValue(
  value: string,
  secrets: string[],
  decrypt: boolean
): Promise<any> {
  if (secrets.length > 0) {
    for (let secret of secrets) {
      if (decrypt) {
        try {
          let { payload: unsignedValue } = await jose.jwtDecrypt(
            value,
            new TextEncoder().encode(secret)
          );
          return unsignedValue;
        } catch (e) {}
      } else {
        try {
          let { payload: unsignedValue } = await jose.jwtVerify(
            value,
            new TextEncoder().encode(secret)
          );
          return unsignedValue;
        } catch (e) {}
      }
    }
  }

  return jose.UnsecuredJWT.decode(value);
}

function warnOnceAboutExpiresCookie(name: string, expires?: Date) {
  warnOnce(
    !expires,
    `The "${name}" cookie has an "expires" property set. ` +
      `This will cause the expires value to not be updated when the session is committed. ` +
      `Instead, you should set the expires value when serializing the cookie. ` +
      `You can use \`commitSession(session, { expires })\` if using a session storage object, ` +
      `or \`cookie.serialize("value", { expires })\` if you're using the cookie directly.`
  );
}
