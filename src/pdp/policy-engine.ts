import type {
  AuthorizationRequest,
  AuthorizationResponse,
  Clause,
  Permission,
  Role,
} from "../shared/types.js";

/**
 * The evaluation context assembled by the PDP from the request, the user's
 * attributes, and the target resource's attributes. ABAC clauses resolve their
 * operands against this object using dotted paths (e.g. "user.department").
 */
export interface EvalContext {
  user: { id: string; tenantId: string } & Record<string, unknown>;
  resource: Record<string, unknown>;
  action: string;
}

/**
 * Core decision function — the heart of the whole system.
 *
 * DENY BY DEFAULT: access is granted only if SOME permission across the user's
 * roles matches the (resource, action) AND its ABAC condition (if any) holds.
 * Pure function: no I/O, no mutation — trivial to unit test and safe on the
 * hot path.
 */
export function evaluate(
  roles: Role[],
  req: AuthorizationRequest,
  ctx: EvalContext,
): AuthorizationResponse {
  for (const role of roles) {
    for (const perm of role.permissions) {
      if (!matchesResource(perm, req.resource)) continue;
      if (!matchesAction(perm, req.action)) continue;
      if (perm.condition && !conditionHolds(perm.condition.allOf, ctx)) continue;
      return {
        decision: "allow",
        reason: `granted by role "${role.name}" via permission ${perm.resource}:${perm.action}`,
      };
    }
  }
  return {
    decision: "deny",
    reason: `no permission grants ${req.action} on ${req.resource}`,
  };
}

function matchesResource(perm: Permission, resource: string): boolean {
  return perm.resource === "*" || perm.resource === resource;
}

function matchesAction(perm: Permission, action: string): boolean {
  return perm.action === "*" || perm.action === action;
}

function conditionHolds(clauses: Clause[], ctx: EvalContext): boolean {
  return clauses.every((c) => clauseHolds(c, ctx));
}

function clauseHolds(clause: Clause, ctx: EvalContext): boolean {
  const left = resolvePath(clause.attribute, ctx);
  const right = resolveOperand(clause.value, ctx);
  switch (clause.op) {
    case "eq":
      return left === right;
    case "neq":
      return left !== right;
    case "in":
      return Array.isArray(right) && right.includes(left as never);
    case "lte":
      return typeof left === "number" && typeof right === "number" && left <= right;
    case "gte":
      return typeof left === "number" && typeof right === "number" && left >= right;
    default:
      return false;
  }
}

/** Right operands prefixed with "$" are themselves context paths. */
function resolveOperand(value: Clause["value"], ctx: EvalContext): unknown {
  if (typeof value === "string" && value.startsWith("$")) {
    return resolvePath(value.slice(1), ctx);
  }
  return value;
}

/** Resolves a dotted path like "user.department" against the context. */
function resolvePath(path: string, ctx: EvalContext): unknown {
  return path.split(".").reduce<unknown>((acc, key) => {
    if (acc && typeof acc === "object" && key in (acc as object)) {
      return (acc as Record<string, unknown>)[key];
    }
    return undefined;
  }, ctx);
}
