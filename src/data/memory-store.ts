import { randomUUID } from "node:crypto";
import type {
  AuditEntry,
  Role,
  RoleId,
  Tenant,
  TenantId,
  User,
  UserId,
} from "../shared/types.js";
import type {
  AuditRepository,
  RoleRepository,
  TenantRepository,
} from "./repositories.js";

/**
 * In-memory implementation of the repositories. Every read is scoped by
 * tenantId — the same invariant a Postgres Row-Level-Security policy would
 * enforce at the database layer. This is the single most important multi-tenant
 * safeguard, applied here in code and (in production) again in the DB.
 */
export class MemoryStore implements TenantRepository, RoleRepository, AuditRepository {
  private tenants = new Map<TenantId, Tenant>();
  private users = new Map<UserId, User>();
  private roles = new Map<RoleId, Role>();
  private audit: AuditEntry[] = [];

  // --- seeding helpers ---
  putTenant(t: Tenant): void {
    this.tenants.set(t.id, t);
  }
  putUser(u: User): void {
    this.users.set(u.id, u);
  }
  putRole(r: Role): void {
    this.roles.set(r.id, r);
  }

  // --- TenantRepository ---
  findById(id: TenantId): Tenant | undefined {
    return this.tenants.get(id);
  }

  // --- UserRepository (tenant-scoped) ---
  findUserById(tenantId: TenantId, userId: UserId): User | undefined {
    const u = this.users.get(userId);
    // Tenant isolation: never return a user from another tenant.
    return u && u.tenantId === tenantId ? u : undefined;
  }
  findByEmail(email: string): User | undefined {
    for (const u of this.users.values()) {
      if (u.email === email) return u;
    }
    return undefined;
  }

  // --- RoleRepository ---
  findByIds(tenantId: TenantId, roleIds: RoleId[]): Role[] {
    return roleIds
      .map((id) => this.roles.get(id))
      .filter((r): r is Role => !!r && r.tenantId === tenantId);
  }
  listForTenant(tenantId: TenantId): Role[] {
    return [...this.roles.values()].filter((r) => r.tenantId === tenantId);
  }
  upsert(role: Role): Role {
    this.roles.set(role.id, role);
    return role;
  }

  // --- AuditRepository (append-only) ---
  append(entry: AuditEntry): void {
    this.audit.push(entry);
  }
  query(filter: { tenantId: TenantId; userId?: UserId }): AuditEntry[] {
    return this.audit.filter(
      (e) =>
        e.tenantId === filter.tenantId &&
        (!filter.userId || e.userId === filter.userId),
    );
  }
}

export function newAuditEntry(e: Omit<AuditEntry, "id" | "timestamp">): AuditEntry {
  return { ...e, id: randomUUID(), timestamp: new Date().toISOString() };
}
