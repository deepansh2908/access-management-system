import { createPublicKey, type JsonWebKey, type KeyObject } from "node:crypto";
import { URLS } from "./config.js";
import { jwksSchema } from "./schemas.js";

/**
 * Fetches and caches the auth service's public verification keys (by `kid`)
 * from its JWKS endpoint. This is how each service verifies tokens in a
 * distributed deployment without holding the private key, and how key rotation
 * propagates: the issuer publishes a new `kid`; verifiers pick it up on the
 * next cache refresh.
 */
const cache = new Map<string, KeyObject>();
let lastFetch = 0;
const TTL_MS = 5 * 60 * 1000;

export async function getVerificationKey(kid: string): Promise<KeyObject> {
  const cached = cache.get(kid);
  if (cached && Date.now() - lastFetch < TTL_MS) return cached;

  const res = await fetch(`${URLS.auth}/.well-known/jwks.json`);
  if (!res.ok) throw new Error(`jwks fetch failed: ${res.status}`);
  const { keys } = jwksSchema.parse(await res.json());

  cache.clear();
  for (const jwk of keys) {
    // jwk is validated to have a string `kid`; the remaining crypto params are
    // passed straight to Node, which validates them when building the key.
    cache.set(jwk.kid, createPublicKey({ key: jwk as JsonWebKey, format: "jwk" }));
  }
  lastFetch = Date.now();

  const key = cache.get(kid);
  if (!key) throw new Error(`no verification key for kid ${kid}`);
  return key;
}
