import { randomUUID } from "node:crypto";
import type { NextFunction, Request, Response } from "express";
import { verifyAccessToken, AUDIENCE, type Audience } from "./jwt.js";
import { URLS } from "./config.js";
import { authorizationResponseSchema } from "./schemas.js";
import type { AccessTokenClaims, AuthorizationRequest } from "./types.js";

/** Express request augmented with the authenticated principal + correlation id. */
export interface AuthedRequest extends Request {
  principal?: AccessTokenClaims;
  requestId?: string;
}

/**
 * Authentication middleware factory: verifies the bearer token (signature,
 * issuer, expiry, AND audience) and attaches the principal + a correlation id.
 * Used by BOTH the gateway and individual services (defense in depth — a service
 * never trusts an unauthenticated caller even if the gateway is bypassed).
 *
 * `audience` defaults to the user plane. Internal service-to-service endpoints
 * pass `AUDIENCE.service` so a user token cannot be replayed against them and a
 * service token cannot be replayed against user routes.
 */
export function authenticate(audience: Audience = AUDIENCE.user) {
  return async (req: AuthedRequest, res: Response, next: NextFunction) => {
    const header = req.header("authorization") ?? "";
    const [scheme, token] = header.split(" ");
    if (scheme !== "Bearer" || !token) {
      return res.status(401).json({ error: "missing bearer token" });
    }
    try {
      req.principal = await verifyAccessToken(token, audience);
    } catch {
      return res.status(401).json({ error: "invalid or expired token" });
    }
    req.requestId = req.header("x-request-id") ?? randomUUID();
    res.setHeader("x-request-id", req.requestId);
    return next();
  };
}

/**
 * Policy Enforcement Point (PEP). Runs in front of a protected endpoint. It:
 *   1. requires an authenticated principal,
 *   2. assembles the authorization request (incl. resource attributes for ABAC),
 *   3. calls the central PDP for an allow/deny decision,
 *   4. enforces it — and FAILS CLOSED on any error.
 *
 * Services never make their own authorization decisions; they only enforce what
 * the PDP returns. In production a short-TTL decision cache would sit here so
 * the PDP is consulted only on cache-miss / policy-version bump (see DESIGN.md).
 */
export function enforce(opts: {
  resource: string;
  action: string;
  resourceId?: (req: AuthedRequest) => string | undefined;
  resourceAttributes?: (
    req: AuthedRequest,
  ) => Record<string, string | number | boolean> | undefined;
}) {
  return async (req: AuthedRequest, res: Response, next: NextFunction) => {
    if (!req.principal) {
      return res.status(401).json({ error: "unauthenticated" });
    }
    const authReq: AuthorizationRequest = {
      tenantId: req.principal.tenantId,
      userId: req.principal.sub,
      resource: opts.resource,
      action: opts.action,
      resourceId: opts.resourceId?.(req),
      resourceAttributes: opts.resourceAttributes?.(req),
      requestId: req.requestId ?? randomUUID(),
    };

    let decision;
    try {
      const r = await fetch(`${URLS.pdp}/authorize`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(authReq),
      });
      if (!r.ok) throw new Error(`pdp status ${r.status}`);
      // Validate the PDP's response — never trust a peer service's shape either.
      decision = authorizationResponseSchema.parse(await r.json());
    } catch {
      // Fail closed: PDP unreachable or returned an unexpected shape -> deny.
      return res.status(503).json({ error: "authorization unavailable" });
    }

    if (decision.decision !== "allow") {
      return res.status(403).json({ error: "forbidden", reason: decision.reason });
    }
    return next();
  };
}
