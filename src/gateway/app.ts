import express, { type Express } from "express";
import { authenticate, type AuthedRequest } from "../shared/pep.js";
import { URLS, RATE_LIMITS } from "../shared/config.js";
import { TokenBucketLimiter, rateLimit, clientIp } from "../shared/rate-limiter.js";

/** Per-tier limit config; defaults from config.ts, overridable for tests. */
export interface GatewayOptions {
  authLimit?: { capacity: number; refillPerSec: number };
  userLimit?: { capacity: number; refillPerSec: number };
}

/**
 * API Gateway — the single entry point for clients. It:
 *   - exposes auth routes publicly (login/token/JWKS), rate-limited by IP,
 *   - authenticates every other request (first PEP layer, defense in depth),
 *   - rate-limits authenticated traffic per tenant:user (noisy-neighbor fairness),
 *   - routes to the right downstream service, propagating the bearer token and
 *     the correlation id.
 *
 * Authorization (the PDP call) happens at the SERVICE-level PEP — closest to the
 * resource and its ABAC attributes — which keeps the gateway thin.
 */
export function createGatewayApp(opts: GatewayOptions = {}): Express {
  const app = express();

  const authCfg = opts.authLimit ?? RATE_LIMITS.auth;
  const userCfg = opts.userLimit ?? RATE_LIMITS.authenticated;
  const authLimiter = new TokenBucketLimiter(authCfg.capacity, authCfg.refillPerSec);
  const userLimiter = new TokenBucketLimiter(userCfg.capacity, userCfg.refillPerSec);

  app.get("/health", (_req, res) => res.json({ status: "ok" }));

  // Public auth routes (no token to log in) — limited by client IP to blunt
  // credential brute-forcing on /login and /token.
  app.use("/api/auth", rateLimit(authLimiter, clientIp), proxy(() => URLS.auth, "/api/auth"));

  // Everything else requires a valid USER token at the edge.
  app.use("/api", authenticate());
  // Per-principal fairness: key by tenantId:userId from the verified token.
  app.use(
    "/api",
    rateLimit(userLimiter, (req) => {
      const p = (req as AuthedRequest).principal;
      return p ? `${p.tenantId}:${p.sub}` : undefined; // undefined => fail open
    }),
  );
  app.use("/api/expense", proxy(() => URLS.expense, "/api/expense"));
  app.use("/api/reporting", proxy(() => URLS.reporting, "/api/reporting"));

  return app;
}

/** Minimal reverse proxy using fetch; forwards method, headers, and body. */
function proxy(target: () => string, prefix: string) {
  return async (req: AuthedRequest, res: express.Response) => {
    const path = req.originalUrl.slice(prefix.length) || "/";
    const headers: Record<string, string> = {};
    if (req.header("authorization")) headers.authorization = req.header("authorization")!;
    if (req.header("content-type")) headers["content-type"] = req.header("content-type")!;
    if (req.requestId) headers["x-request-id"] = req.requestId;

    const hasBody = req.method !== "GET" && req.method !== "HEAD";
    const body = hasBody ? await readRawBody(req) : undefined;

    try {
      const upstream = await fetch(`${target()}${path}`, { method: req.method, headers, body });
      res.status(upstream.status);
      const ct = upstream.headers.get("content-type");
      if (ct) res.setHeader("content-type", ct);
      res.send(await upstream.text());
    } catch {
      res.status(502).json({ error: "bad gateway" });
    }
  };
}

function readRawBody(req: express.Request): Promise<string> {
  return new Promise((resolve) => {
    let data = "";
    req.on("data", (c) => (data += c));
    req.on("end", () => resolve(data));
  });
}
