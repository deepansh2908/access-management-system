import express, { type Express } from "express";
import { authenticate, enforce, type AuthedRequest } from "../../shared/pep.js";
import { URLS } from "../../shared/config.js";
import { internalExpensesSchema, tokenResponseSchema } from "../../shared/schemas.js";

/**
 * Reporting service. Demonstrates cross-service authorization and
 * service-to-service communication: to build a report it calls the Expense
 * service using its OWN service token (client-credentials grant). The downstream
 * call is itself authenticated and authorized — there is no implicit trust
 * between services, and the service token carries a least-privilege role.
 */
export function createReportingApp(): Express {
  const app = express();
  app.use(express.json());

  app.get("/health", (_req, res) => res.json({ status: "ok" }));
  app.use(authenticate()); // user-facing routes -> user-audience tokens

  app.get(
    "/reports/expense-summary",
    enforce({ resource: "report", action: "read" }),
    async (req: AuthedRequest, res) => {
      const tenantId = req.principal!.tenantId;
      try {
        // 1. Obtain a scoped service token (client-credentials grant).
        const tokenRes = await fetch(`${URLS.auth}/token`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            clientId: "reporting-service",
            clientSecret: "service-secret",
            tenantId,
          }),
        });
        if (!tokenRes.ok) throw new Error("service token request failed");
        const { accessToken } = tokenResponseSchema.parse(await tokenRes.json());

        // 2. Call the Expense service with the service token + correlation id.
        const expRes = await fetch(`${URLS.expense}/internal/expenses`, {
          headers: {
            authorization: `Bearer ${accessToken}`,
            "x-request-id": req.requestId ?? "",
          },
        });
        if (!expRes.ok) throw new Error(`expense service status ${expRes.status}`);
        const expenses = internalExpensesSchema.parse(await expRes.json());

        // 3. Aggregate.
        const total = expenses.reduce((s, e) => s + e.amount, 0);
        const pending = expenses.filter((e) => e.status === "pending").length;
        res.json({ tenantId, count: expenses.length, total, pending });
      } catch {
        res.status(502).json({ error: "failed to build report" });
      }
    },
  );

  return app;
}
