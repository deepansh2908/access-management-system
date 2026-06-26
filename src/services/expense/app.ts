import { randomUUID } from "node:crypto";
import express, { type Express, type Response, type NextFunction } from "express";
import { authenticate, enforce, type AuthedRequest } from "../../shared/pep.js";
import { AUDIENCE } from "../../shared/jwt.js";
import { createExpenseSchema } from "../../shared/schemas.js";
import type { Expense } from "../../shared/types.js";
import type { ExpenseRepository } from "../../data/repositories.js";

type ExpenseRequest = AuthedRequest & { expense?: Expense };

/**
 * Expense Management service. Demonstrates:
 *  - tenant-scoped data access via an injected ExpenseRepository (the same
 *    swap-seam pattern as the identity/policy plane; Postgres+RLS in prod),
 *  - ABAC enforcement (employees read only their own; managers approve only in
 *    their department) by supplying resource attributes to the PDP.
 */
export function createExpenseApp(expenses: ExpenseRepository): Express {
  const app = express();
  app.use(express.json());

  app.get("/health", (_req, res) => res.json({ status: "ok" }));

  // User-facing routes accept only USER-audience tokens; the internal
  // service-to-service endpoint accepts only SERVICE-audience tokens. This keeps
  // the user plane and the service plane from accepting each other's tokens.
  const userAuth = authenticate(AUDIENCE.user);
  const serviceAuth = authenticate(AUDIENCE.service);

  // Loads the target expense BEFORE the PDP is consulted so its attributes are
  // available for ABAC. The repository is tenant-scoped, so a cross-tenant id
  // simply resolves to undefined -> 404 (not 403): no hand-written tenant check,
  // and the resource's existence isn't leaked to other tenants.
  const loadExpense = (req: ExpenseRequest, res: Response, next: NextFunction) => {
    const exp = req.params.id
      ? expenses.findById(req.principal!.tenantId, req.params.id)
      : undefined;
    if (!exp) {
      return res.status(404).json({ error: "expense not found" });
    }
    req.expense = exp;
    return next();
  };

  const expenseAttrs = (req: AuthedRequest) => {
    const exp = (req as ExpenseRequest).expense;
    return exp ? { ownerId: exp.ownerId, department: exp.department } : undefined;
  };

  // Create an expense.
  app.post(
    "/expenses",
    userAuth,
    enforce({ resource: "expense", action: "create" }),
    (req: AuthedRequest, res) => {
      const parsed = createExpenseSchema.safeParse(req.body ?? {});
      if (!parsed.success) {
        return res.status(400).json({ error: "invalid expense", issues: parsed.error.issues });
      }
      const exp: Expense = {
        id: `exp-${randomUUID().slice(0, 8)}`,
        tenantId: req.principal!.tenantId,
        ownerId: req.principal!.sub,
        department: parsed.data.department,
        amount: parsed.data.amount,
        status: "pending",
      };
      expenses.save(exp);
      return res.status(201).json(exp);
    },
  );

  // Read a single expense (ABAC: own-only for employees).
  app.get(
    "/expenses/:id",
    userAuth,
    loadExpense,
    enforce({
      resource: "expense",
      action: "read",
      resourceId: (req) => req.params.id,
      resourceAttributes: expenseAttrs,
    }),
    (req: ExpenseRequest, res) => res.json(req.expense),
  );

  // Approve an expense (ABAC: same-department managers only).
  app.post(
    "/expenses/:id/approve",
    userAuth,
    loadExpense,
    enforce({
      resource: "expense",
      action: "approve",
      resourceId: (req) => req.params.id,
      resourceAttributes: expenseAttrs,
    }),
    (req: ExpenseRequest, res) => {
      const updated: Expense = { ...req.expense!, status: "approved" };
      expenses.save(updated);
      res.json(updated);
    },
  );

  // Internal endpoint for service-to-service aggregation (used by reporting).
  // Still authenticated + authorized — services are NOT implicitly trusted.
  app.get(
    "/internal/expenses",
    serviceAuth,
    enforce({ resource: "expense", action: "read" }),
    (req: AuthedRequest, res) => {
      res.json(expenses.listByTenant(req.principal!.tenantId));
    },
  );

  return app;
}
