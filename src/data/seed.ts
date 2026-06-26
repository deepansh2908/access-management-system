import { MemoryStore } from "./memory-store.js";

/**
 * Seeds a deterministic multi-tenant dataset:
 *  - Tenant "acme"  : pool-isolated org with admin / manager / employee roles
 *  - Tenant "globex": a separate tenant used to prove tenant isolation
 *
 * Roles demonstrate RBAC (role -> permissions) layered with ABAC conditions:
 *  - an employee may only READ their OWN expenses,
 *  - a manager may APPROVE expenses only within their OWN department.
 *
 * Each tenant also gets a least-privilege SERVICE identity for the reporting
 * service's service-to-service call.
 */
export function seed(): MemoryStore {
  const store = new MemoryStore();

  for (const tenantId of ["acme", "globex"]) {
    store.putTenant({ id: tenantId, name: tenantId, status: "active", isolation: "pool" });

    // admin: full access within the tenant
    store.putRole({
      id: `${tenantId}-admin`,
      tenantId,
      name: "admin",
      permissions: [{ resource: "*", action: "*" }],
    });

    // manager: read all expenses; approve expenses in own department; read reports
    store.putRole({
      id: `${tenantId}-manager`,
      tenantId,
      name: "manager",
      permissions: [
        { resource: "expense", action: "read" },
        {
          resource: "expense",
          action: "approve",
          condition: {
            allOf: [
              { attribute: "resource.department", op: "eq", value: "$user.department" },
            ],
          },
        },
        { resource: "expense", action: "create" },
        { resource: "report", action: "read" },
      ],
    });

    // employee: create expenses; read ONLY their own expenses
    store.putRole({
      id: `${tenantId}-employee`,
      tenantId,
      name: "employee",
      permissions: [
        { resource: "expense", action: "create" },
        {
          resource: "expense",
          action: "read",
          condition: {
            allOf: [{ attribute: "resource.ownerId", op: "eq", value: "$user.id" }],
          },
        },
      ],
    });

    // service-account role: least-privilege grant for the reporting service's
    // service-to-service call (read expenses only — NOT full admin).
    store.putRole({
      id: `${tenantId}-svc-reporting`,
      tenantId,
      name: "svc-reporting",
      permissions: [{ resource: "expense", action: "read" }],
    });

    // the reporting service's per-tenant service identity
    store.putUser({
      id: `reporting-service@${tenantId}`,
      tenantId,
      email: `reporting-service@${tenantId}.svc`,
      password: "n/a",
      roleIds: [`${tenantId}-svc-reporting`],
      attributes: {},
      status: "active",
    });
  }

  // --- Acme users ---
  store.putUser({
    id: "acme-alice",
    tenantId: "acme",
    email: "alice@acme.test",
    password: "password",
    roleIds: ["acme-admin"],
    attributes: { department: "finance", level: 10 },
    status: "active",
  });
  store.putUser({
    id: "acme-bob",
    tenantId: "acme",
    email: "bob@acme.test",
    password: "password",
    roleIds: ["acme-manager"],
    attributes: { department: "engineering", level: 5 },
    status: "active",
  });
  store.putUser({
    id: "acme-carol",
    tenantId: "acme",
    email: "carol@acme.test",
    password: "password",
    roleIds: ["acme-employee"],
    attributes: { department: "engineering", level: 2 },
    status: "active",
  });

  // --- Globex user (used to prove cross-tenant access is denied) ---
  store.putUser({
    id: "globex-dave",
    tenantId: "globex",
    email: "dave@globex.test",
    password: "password",
    roleIds: ["globex-admin"],
    attributes: { department: "ops", level: 10 },
    status: "active",
  });

  return store;
}
