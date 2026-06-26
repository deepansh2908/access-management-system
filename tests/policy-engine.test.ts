import { describe, expect, it } from "vitest";
import { evaluate, type EvalContext } from "../src/pdp/policy-engine.js";
import type { AuthorizationRequest, Role } from "../src/shared/types.js";

const employeeRole: Role = {
  id: "t-employee",
  tenantId: "t",
  name: "employee",
  permissions: [
    { resource: "expense", action: "create" },
    {
      resource: "expense",
      action: "read",
      condition: { allOf: [{ attribute: "resource.ownerId", op: "eq", value: "$user.id" }] },
    },
  ],
};

const managerRole: Role = {
  id: "t-manager",
  tenantId: "t",
  name: "manager",
  permissions: [
    {
      resource: "expense",
      action: "approve",
      condition: {
        allOf: [{ attribute: "resource.department", op: "eq", value: "$user.department" }],
      },
    },
  ],
};

const adminRole: Role = {
  id: "t-admin",
  tenantId: "t",
  name: "admin",
  permissions: [{ resource: "*", action: "*" }],
};

function req(over: Partial<AuthorizationRequest>): AuthorizationRequest {
  return { tenantId: "t", userId: "u1", resource: "expense", action: "read", requestId: "r1", ...over };
}

function ctx(user: Record<string, unknown>, resource: Record<string, unknown>): EvalContext {
  return { user: { id: "u1", tenantId: "t", ...user }, resource, action: "read" };
}

describe("policy engine (RBAC + ABAC, deny-by-default)", () => {
  it("denies by default when no permission matches", () => {
    expect(evaluate([employeeRole], req({ action: "delete" }), ctx({}, {})).decision).toBe("deny");
  });

  it("grants an RBAC permission with no condition", () => {
    expect(evaluate([employeeRole], req({ action: "create" }), ctx({}, {})).decision).toBe("allow");
  });

  it("ABAC: employee can read their OWN expense", () => {
    const r = evaluate([employeeRole], req({ action: "read" }), ctx({ id: "u1" }, { ownerId: "u1" }));
    expect(r.decision).toBe("allow");
  });

  it("ABAC: employee cannot read someone else's expense", () => {
    const r = evaluate([employeeRole], req({ action: "read" }), ctx({ id: "u1" }, { ownerId: "u2" }));
    expect(r.decision).toBe("deny");
  });

  it("ABAC: manager approves only within their own department", () => {
    const same = evaluate([managerRole], req({ action: "approve" }), ctx({ department: "eng" }, { department: "eng" }));
    const diff = evaluate([managerRole], req({ action: "approve" }), ctx({ department: "eng" }, { department: "finance" }));
    expect(same.decision).toBe("allow");
    expect(diff.decision).toBe("deny");
  });

  it("wildcard admin permission grants any action on any resource", () => {
    const r = evaluate([adminRole], req({ resource: "payroll", action: "delete" }), ctx({}, {}));
    expect(r.decision).toBe("allow");
  });

  it("returns a human-readable reason on allow", () => {
    const r = evaluate([adminRole], req({ action: "create" }), ctx({}, {}));
    expect(r.reason).toContain("admin");
  });
});
