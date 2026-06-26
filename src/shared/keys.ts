import { generateKeyPairSync } from "node:crypto";

/**
 * Asymmetric signing keys for access tokens.
 *
 * The auth service holds the private key and signs tokens. Every other service
 * verifies with the PUBLIC key fetched from the JWKS endpoint — so no shared
 * secret is ever distributed, and key rotation only touches the auth service.
 *
 * Production: these come from a KMS / HSM, and JWKS publishes multiple keys
 * (by `kid`) so a new key can be rolled out before the old one is retired
 * (zero-downtime rotation). Here we generate one pair at process startup.
 */
const { privateKey, publicKey } = generateKeyPairSync("rsa", {
  modulusLength: 2048,
});

export const KEY_ID = "auth-key-1";

export const SIGNING_KEY = privateKey.export({
  type: "pkcs8",
  format: "pem",
}) as string;

/** JWKS representation served at /.well-known/jwks.json. */
export function jwks() {
  const jwk = publicKey.export({ format: "jwk" });
  return { keys: [{ ...jwk, kid: KEY_ID, use: "sig", alg: "RS256" }] };
}
