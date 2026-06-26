import type {
  AuditEntry,
  Expense,
  Role,
  RoleId,
  Tenant,
  TenantId,
  User,
  UserId,
} from "../shared/types.js";

/**
 * Repository interfaces decouple business logic from storage. Swapping the
 * in-memory implementation for Postgres (shared tables + Row-Level Security for
 * tenant isolation) requires NO changes to the PDP or services — only a new
 * implementation of these interfaces. This is the seam the DESIGN doc relies on
 * when it says "the Postgres+RLS swap is mechanical".
 */

export interface TenantRepository {
  findById(id: TenantId): Tenant | undefined;
}

export interface UserRepository {
  /** Tenant-scoped: never returns a user from another tenant. */
  findById(tenantId: TenantId, userId: UserId): User | undefined;
  findByEmail(email: string): User | undefined;
}

export interface RoleRepository {
  findByIds(tenantId: TenantId, roleIds: RoleId[]): Role[];
  listForTenant(tenantId: TenantId): Role[];
  /** Dynamic role management: upsert at runtime, no redeploy. */
  upsert(role: Role): Role;
}

export interface AuditRepository {
  /** Append-only: there is deliberately no update or delete. */
  append(entry: AuditEntry): void;
  query(filter: { tenantId: TenantId; userId?: UserId }): AuditEntry[];
}

/**
 * The Expense service's own data, behind the same kind of tenant-scoped
 * interface as the identity/policy plane. `findById` returns nothing for a
 * cross-tenant id — the same invariant Postgres Row-Level Security enforces —
 * so callers don't hand-check `tenantId` themselves.
 */
export interface ExpenseRepository {
  findById(tenantId: TenantId, id: string): Expense | undefined;
  listByTenant(tenantId: TenantId): Expense[];
  save(expense: Expense): Expense;
}
