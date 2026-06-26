import express, { type Express } from "express";
import type { MemoryStore } from "../data/memory-store.js";
import { newAuditEntry } from "../data/memory-store.js";
import type { AuthorizationRequest, Role } from "../shared/types.js";
import { authorizationRequestSchema, roleUpsertSchema } from "../shared/schemas.js";
import { authenticate, type AuthedRequest } from "../shared/pep.js";
import { evaluate, type EvalContext } from "./policy-engine.js";

/**
 * The Policy Decision Point (PDP). Stateless per request: it loads the user's
 * roles, assembles the evaluation context, runs the policy engine, records an
 * audit entry, and returns allow/deny with a human-readable reason.
 *
 * Centralizing decisions here (rather than embedding logic in each service)
 * means policy changes take effect everywhere at once, and every decision is
 * audited in one place. Also exposes dynamic role management + audit query.
 */
export function createPdpApp(store: MemoryStore): Express {
  const app = express();
  app.use(express.json());

  app.get("/health", (_req, res) => res.json({ status: "ok" }));

  app.post("/authorize", (req, res) => {
    const parsed = authorizationRequestSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ error: "invalid authorization request", issues: parsed.error.issues });
    }
    const authReq = parsed.data;

    const tenant = store.findById(authReq.tenantId);
    if (!tenant || tenant.status !== "active") {
      return deny(res, store, authReq, "tenant not found or inactive");
    }

    // Tenant isolation: a user id from another tenant resolves to undefined.
    const user = store.findUserById(authReq.tenantId, authReq.userId);
    if (!user || user.status !== "active") {
      return deny(res, store, authReq, "user not found, disabled, or cross-tenant");
    }

    const roles: Role[] = store.findByIds(authReq.tenantId, user.roleIds);
    const ctx: EvalContext = {
      user: { id: user.id, tenantId: user.tenantId, ...user.attributes },
      resource: { id: authReq.resourceId, ...(authReq.resourceAttributes ?? {}) },
      action: authReq.action,
    };

    const result = evaluate(roles, authReq, ctx);
    store.append(
      newAuditEntry({
        tenantId: authReq.tenantId,
        userId: authReq.userId,
        resource: authReq.resource,
        action: authReq.action,
        resourceId: authReq.resourceId,
        decision: result.decision,
        reason: result.reason,
        requestId: authReq.requestId,
      }),
    );
    return res.json(result);
  });

  /**
   * Guard for administrative endpoints. The management/audit APIs are not
   * public: the caller must (1) present a valid user token, (2) operate within
   * their OWN tenant (the URL `:tenantId` must match the token's tenant — this
   * blocks cross-tenant reads), and (3) hold the required permission, evaluated
   * locally via the same policy engine (no HTTP self-call, no recursion).
   */
  const adminGuard = (resource: string, action: string) => [
    authenticate(),
    (req: AuthedRequest, res: express.Response, next: express.NextFunction) => {
      const p = req.principal!;
      if (p.tenantId !== req.params.tenantId) {
        return res.status(403).json({ error: "cross-tenant access denied" });
      }
      const roles = store.findByIds(p.tenantId, p.roles);
      const decision = evaluate(
        roles,
        { tenantId: p.tenantId, userId: p.sub, resource, action, requestId: req.requestId ?? "admin" },
        { user: { id: p.sub, tenantId: p.tenantId }, resource: {}, action },
      );
      if (decision.decision !== "allow") {
        return res.status(403).json({ error: "forbidden", reason: decision.reason });
      }
      return next();
    },
  ];

  // --- Dynamic role/permission management (no redeploy required) ---
  // Reading roles requires `role:read`; mutating requires `role:write`.
  app.get("/tenants/:tenantId/roles", adminGuard("role", "read"), (req: AuthedRequest, res: express.Response) => {
    res.json(store.listForTenant(req.params.tenantId!));
  });

  app.put("/tenants/:tenantId/roles/:roleId", adminGuard("role", "write"), (req: AuthedRequest, res: express.Response) => {
    const parsed = roleUpsertSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ error: "invalid role", issues: parsed.error.issues });
    }
    const role: Role = {
      id: req.params.roleId!,
      tenantId: req.params.tenantId!,
      name: parsed.data.name ?? req.params.roleId!,
      permissions: parsed.data.permissions,
    };
    res.json(store.upsert(role));
  });

  // --- Audit query (operational concern: investigate an access denial) ---
  // Requires `audit:read`, scoped to the caller's own tenant.
  app.get("/tenants/:tenantId/audit", adminGuard("audit", "read"), (req: AuthedRequest, res: express.Response) => {
    const userId = typeof req.query.userId === "string" ? req.query.userId : undefined;
    res.json(store.query({ tenantId: req.params.tenantId!, userId }));
  });

  return app;
}

function deny(
  res: express.Response,
  store: MemoryStore,
  req: AuthorizationRequest,
  reason: string,
) {
  store.append(
    newAuditEntry({
      tenantId: req.tenantId,
      userId: req.userId,
      resource: req.resource,
      action: req.action,
      resourceId: req.resourceId,
      decision: "deny",
      reason,
      requestId: req.requestId,
    }),
  );
  return res.json({ decision: "deny", reason });
}
