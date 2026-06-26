import jwt from "jsonwebtoken";
import type { AccessTokenClaims } from "./types.js";
import { accessTokenClaimsSchema } from "./schemas.js";
import { KEY_ID, SIGNING_KEY } from "./keys.js";
import { getVerificationKey } from "./jwks-client.js";
import { ACCESS_TTL_SECONDS } from "./config.js";

const ISSUER = "auth.access-control.local";

/**
 * Token audiences separate the two planes:
 *  - `user`    → end-user tokens, accepted on user-facing (gateway/service) routes
 *  - `service` → service-to-service tokens, accepted ONLY on internal endpoints
 * Enforcing audience at verify time prevents a service token being replayed as a
 * user token (and vice-versa) — the two are not interchangeable credentials.
 */
export const AUDIENCE = { user: "api", service: "internal-services" } as const;
export type Audience = (typeof AUDIENCE)[keyof typeof AUDIENCE];

/** Issues a signed, short-lived access token (RS256). */
export function signAccessToken(claims: AccessTokenClaims): string {
  return jwt.sign(claims, SIGNING_KEY, {
    algorithm: "RS256",
    keyid: KEY_ID,
    issuer: ISSUER,
    audience: claims.type === "service" ? AUDIENCE.service : AUDIENCE.user,
    expiresIn: ACCESS_TTL_SECONDS,
  });
}

/**
 * Verifies a token's signature, issuer, expiry AND audience using the issuer's
 * PUBLIC key, resolved by `kid` from the JWKS endpoint (cached). No shared
 * secret is involved, so this works across independently deployed services.
 *
 * `expectedAudience` is REQUIRED so every call site is explicit about which
 * plane it accepts — a token minted for a different audience is rejected.
 */
export async function verifyAccessToken(
  token: string,
  expectedAudience: Audience,
): Promise<AccessTokenClaims> {
  const decoded = jwt.decode(token, { complete: true });
  const kid = decoded?.header.kid ?? KEY_ID;
  const key = await getVerificationKey(kid);
  const payload = jwt.verify(token, key, {
    algorithms: ["RS256"],
    issuer: ISSUER,
    audience: expectedAudience,
  });
  // Validate the claim shape rather than asserting it — a syntactically valid
  // token signed for a different schema is still rejected here.
  return accessTokenClaimsSchema.parse(payload);
}
