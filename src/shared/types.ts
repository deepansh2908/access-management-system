// Core domain model for the access-control system.
// All identifiers are opaque strings; tenantId scopes every entity.
//
// Types that cross a trust boundary (Permission/Condition/Clause and the
// authorization request/response/claims) are inferred from the Zod schemas in
// schemas.ts, so validation and types share one source of truth. Purely
// internal entities (Tenant/User/Role/AuditEntry) stay as interfaces.

import type { z } from "zod";
import type {
  accessTokenClaimsSchema,
  authorizationRequestSchema,
  authorizationResponseSchema,
  clauseSchema,
  conditionSchema,
  permissionSchema,
} from "./schemas.js";

export type TenantId = string;
export type UserId = string;
export type RoleId = string;

/** A tenant is an isolated customer organization. */
export interface Tenant {
  id: TenantId;
  name: string;
  status: "active" | "suspended";
  /** Isolation tier: "pool" = shared tables; "silo" = dedicated DB (premium). */
  isolation: "pool" | "silo";
}

/** A user always belongs to exactly one tenant. */
export interface User {
  id: UserId;
  tenantId: TenantId;
  email: string;
  /** Bcrypt/argon2 in production; plaintext here is seed-only (flagged in docs). */
  password: string;
  /** Roles granted to this user within the tenant. */
  roleIds: RoleId[];
  /** Arbitrary attributes used by ABAC conditions (e.g. department, level). */
  attributes: Record<string, string | number | boolean>;
  status: "active" | "disabled";
}

/**
 * A permission is a (resource, action) pair, optionally constrained by an ABAC
 * condition. `resource`/`action` accept "*" wildcards. A condition turns coarse
 * RBAC into fine-grained ABAC. Inferred from `permissionSchema`.
 */
export type Permission = z.infer<typeof permissionSchema>;

/**
 * A condition compares request-context attributes; every clause is ANDed.
 * A tiny DSL rather than a full policy language (Rego/Cedar) — see DESIGN §14.
 * Inferred from `conditionSchema` / `clauseSchema`.
 */
export type Condition = z.infer<typeof conditionSchema>;
export type Clause = z.infer<typeof clauseSchema>;

/** An expense — the Expense service's domain resource. Tenant-scoped like all
 *  entities; `ownerId`/`department` feed ABAC conditions at the PDP. */
export interface Expense {
  id: string;
  tenantId: TenantId;
  ownerId: UserId;
  department: string;
  amount: number;
  status: "pending" | "approved";
}

/** Roles are defined per-tenant and may be edited at runtime (dynamic RBAC). */
export interface Role {
  id: RoleId;
  tenantId: TenantId;
  name: string;
  permissions: Permission[];
}

/** Immutable, append-only record of every authorization decision. */
export interface AuditEntry {
  id: string;
  timestamp: string;
  tenantId: TenantId;
  userId: UserId;
  resource: string;
  action: string;
  resourceId?: string;
  decision: "allow" | "deny";
  reason: string;
  /** Correlation id propagated across services for one logical request. */
  requestId: string;
}

/** The decision request a PEP sends to the PDP. Inferred from its schema. */
export type AuthorizationRequest = z.infer<typeof authorizationRequestSchema>;

/** The PDP's decision. Inferred from its schema. */
export type AuthorizationResponse = z.infer<typeof authorizationResponseSchema>;

/** Claims embedded in the access token issued by the auth service. */
export type AccessTokenClaims = z.infer<typeof accessTokenClaimsSchema>;
