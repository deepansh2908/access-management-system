import express, { type Express } from "express";
import type { MemoryStore } from "../data/memory-store.js";
import { signAccessToken } from "../shared/jwt.js";
import { jwks } from "../shared/keys.js";
import { ACCESS_TTL_SECONDS } from "../shared/config.js";
import { loginSchema, serviceTokenSchema } from "../shared/schemas.js";

/**
 * Authentication service. Validates credentials and issues short-lived, signed
 * access tokens carrying tenant + role claims. Publishes JWKS so other services
 * verify tokens without a shared secret. Issues service-to-service tokens via
 * the client-credentials grant (each bound to a least-privilege identity).
 */
export function createAuthApp(store: MemoryStore): Express {
  const app = express();
  app.use(express.json());

  app.get("/health", (_req, res) => res.json({ status: "ok" }));

  // JWKS endpoint — public keys for token verification + rotation.
  app.get("/.well-known/jwks.json", (_req, res) => res.json(jwks()));

  // End-user login (password grant, simplified).
  app.post("/login", (req, res) => {
    const parsed = loginSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ error: "email and password required" });
    }
    const { email, password } = parsed.data;
    const user = store.findByEmail(email);
    // Constant message — avoids leaking which part was wrong.
    if (!user || user.password !== password || user.status !== "active") {
      return res.status(401).json({ error: "invalid credentials" });
    }
    const token = signAccessToken({
      sub: user.id,
      tenantId: user.tenantId,
      roles: user.roleIds,
      email: user.email,
      type: "user",
    });
    return res.json({ accessToken: token, tokenType: "Bearer", expiresIn: ACCESS_TTL_SECONDS });
  });

  // Service-to-service: client-credentials grant.
  app.post("/token", (req, res) => {
    const parsed = serviceTokenSchema.safeParse(req.body);
    // Demo secret; production uses per-service rotated credentials + mTLS.
    if (!parsed.success || parsed.data.clientSecret !== "service-secret") {
      return res.status(401).json({ error: "invalid client credentials" });
    }
    const { clientId, tenantId } = parsed.data;
    // Resolve the per-tenant service identity so the token carries a SCOPED,
    // least-privilege role (not admin). The PDP treats it like any principal.
    const serviceUser = store.findUserById(tenantId, `${clientId}@${tenantId}`);
    if (!serviceUser || serviceUser.status !== "active") {
      return res.status(401).json({ error: "unknown service identity" });
    }
    const token = signAccessToken({
      sub: serviceUser.id,
      tenantId,
      roles: serviceUser.roleIds,
      email: serviceUser.email,
      type: "service",
    });
    return res.json({ accessToken: token, tokenType: "Bearer", expiresIn: ACCESS_TTL_SECONDS });
  });

  return app;
}
