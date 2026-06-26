import type { Expense, TenantId } from "../shared/types.js";
import type { ExpenseRepository } from "./repositories.js";

/**
 * In-memory ExpenseRepository. Every read is tenant-scoped — `findById` returns
 * undefined for an id that belongs to another tenant, mirroring a Postgres
 * Row-Level-Security policy. Swapping this for a real DB requires no change to
 * the Expense service, exactly like the identity/policy store.
 */
export class InMemoryExpenseRepository implements ExpenseRepository {
  private byId = new Map<string, Expense>();

  constructor(seed: Expense[] = []) {
    for (const e of seed) this.byId.set(e.id, e);
  }

  findById(tenantId: TenantId, id: string): Expense | undefined {
    const e = this.byId.get(id);
    return e && e.tenantId === tenantId ? e : undefined;
  }

  listByTenant(tenantId: TenantId): Expense[] {
    return [...this.byId.values()].filter((e) => e.tenantId === tenantId);
  }

  save(expense: Expense): Expense {
    this.byId.set(expense.id, expense);
    return expense;
  }
}

/** A repository pre-seeded with the demo expenses (owned by acme users). */
export function seededExpenseRepository(): InMemoryExpenseRepository {
  return new InMemoryExpenseRepository([
    { id: "exp-1", tenantId: "acme", ownerId: "acme-carol", department: "engineering", amount: 100, status: "pending" },
    { id: "exp-2", tenantId: "acme", ownerId: "acme-bob", department: "engineering", amount: 250, status: "pending" },
  ]);
}
