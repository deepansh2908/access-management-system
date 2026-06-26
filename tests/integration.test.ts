import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { Server } from "node:http";
import { seed } from "../src/data/seed.js";
import { seededExpenseRepository } from "../src/data/expense-store.js";
import { PORTS, URLS } from "../src/shared/config.js";
import { createAuthApp } from "../src/auth-service/app.js";
import { createPdpApp } from "../src/pdp/app.js";
import { createGatewayApp } from "../src/gateway/app.js";
import { createExpenseApp } from "../src/services/expense/app.js";
import { createReportingApp } from "../src/services/reporting/app.js";

const servers: Server[] = [];
const GW = `http://localhost:${PORTS.gateway}`;

function listen(app: ReturnType<typeof createGatewayApp>, port: number) {
  return new Promise<void>((resolve) => {
    servers.push(app.listen(port, resolve));
  });
}

async function login(email: string): Promise<string> {
  const r = await fetch(`${GW}/api/auth/login`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ email, password: "password" }),
  });
  return ((await r.json()) as { accessToken: string }).accessToken;
}

function authed(token: string, init: RequestInit = {}): RequestInit {
  return { ...init, headers: { ...(init.headers ?? {}), authorization: `Bearer ${token}` } };
}

beforeAll(async () => {
  const store = seed();
  await listen(createAuthApp(store), PORTS.auth);
  await listen(createPdpApp(store), PORTS.pdp);
  await listen(createExpenseApp(seededExpenseRepository()), PORTS.expense);
  await listen(createReportingApp(), PORTS.reporting);
  await listen(createGatewayApp(), PORTS.gateway);
});

afterAll(() => {
  for (const s of servers) s.close();
});

describe("end-to-end access control", () => {
  it("rejects unauthenticated requests at the gateway", async () => {
    expect((await fetch(`${GW}/api/expense/expenses/exp-1`)).status).toBe(401);
  });

  it("rejects a tampered/invalid token", async () => {
    const r = await fetch(`${GW}/api/expense/expenses/exp-1`, authed("not.a.jwt"));
    expect(r.status).toBe(401);
  });

  it("employee can read their OWN expense (RBAC+ABAC allow)", async () => {
    const token = await login("carol@acme.test");
    expect((await fetch(`${GW}/api/expense/expenses/exp-1`, authed(token))).status).toBe(200);
  });

  it("employee is FORBIDDEN from reading another user's expense (ABAC deny)", async () => {
    const token = await login("carol@acme.test");
    expect((await fetch(`${GW}/api/expense/expenses/exp-2`, authed(token))).status).toBe(403);
  });

  it("manager can approve an expense within their department", async () => {
    const token = await login("bob@acme.test");
    const r = await fetch(`${GW}/api/expense/expenses/exp-2/approve`, authed(token, { method: "POST" }));
    expect(r.status).toBe(200);
    expect(((await r.json()) as { status: string }).status).toBe("approved");
  });

  it("enforces tenant isolation: another tenant cannot see acme data (404, not 403)", async () => {
    const token = await login("dave@globex.test");
    expect((await fetch(`${GW}/api/expense/expenses/exp-1`, authed(token))).status).toBe(404);
  });

  it("supports a cross-service report via service-to-service auth", async () => {
    const token = await login("alice@acme.test");
    const r = await fetch(`${GW}/api/reporting/reports/expense-summary`, authed(token));
    expect(r.status).toBe(200);
    const body = (await r.json()) as { tenantId: string; count: number };
    expect(body.tenantId).toBe("acme");
    expect(body.count).toBeGreaterThan(0);
  });

  it("records append-only audit entries for decisions (incl. denials)", async () => {
    const admin = await login("alice@acme.test"); // audit:read via admin role
    const entries = (await (
      await fetch(`${URLS.pdp}/tenants/acme/audit?userId=acme-carol`, authed(admin))
    ).json()) as Array<{ decision: string }>;
    expect(entries.length).toBeGreaterThan(0);
    expect(entries.some((e) => e.decision === "deny")).toBe(true);
  });

  it("supports dynamic role management at runtime (admin only)", async () => {
    const admin = await login("alice@acme.test");
    // Grant a brand-new permission to a fresh role and confirm it persists.
    const put = await fetch(`${URLS.pdp}/tenants/acme/roles/acme-auditor`, {
      method: "PUT",
      headers: { "content-type": "application/json", authorization: `Bearer ${admin}` },
      body: JSON.stringify({ name: "auditor", permissions: [{ resource: "report", action: "read" }] }),
    });
    expect(put.status).toBe(200);
    const roles = (await (
      await fetch(`${URLS.pdp}/tenants/acme/roles`, authed(admin))
    ).json()) as Array<{ id: string }>;
    expect(roles.some((r) => r.id === "acme-auditor")).toBe(true);
  });
});

describe("token audience separation (plane isolation)", () => {
  // A service token (client-credentials, aud=internal-services) must NOT be
  // accepted on a user-facing route (aud=api).
  it("rejects a service token on a user endpoint", async () => {
    const tokenRes = await fetch(`${GW}/api/auth/token`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        clientId: "reporting-service",
        clientSecret: "service-secret",
        tenantId: "acme",
      }),
    });
    const { accessToken } = (await tokenRes.json()) as { accessToken: string };
    const r = await fetch(`${GW}/api/expense/expenses/exp-1`, authed(accessToken));
    expect(r.status).toBe(401); // wrong audience -> rejected at the edge
  });
});

describe("PDP admin endpoint authorization", () => {
  const roleUrl = `${URLS.pdp}/tenants/acme/roles/acme-temp`;
  const body = JSON.stringify({ name: "temp", permissions: [] });

  it("rejects role management with NO token (401)", async () => {
    const r = await fetch(roleUrl, {
      method: "PUT",
      headers: { "content-type": "application/json" },
      body,
    });
    expect(r.status).toBe(401);
  });

  it("rejects role management for a non-admin user (403)", async () => {
    const carol = await login("carol@acme.test"); // employee, no role:write
    const r = await fetch(roleUrl, {
      method: "PUT",
      headers: { "content-type": "application/json", authorization: `Bearer ${carol}` },
      body,
    });
    expect(r.status).toBe(403);
  });

  it("blocks cross-tenant audit access even for an admin (403)", async () => {
    const acmeAdmin = await login("alice@acme.test");
    const r = await fetch(`${URLS.pdp}/tenants/globex/audit`, authed(acmeAdmin));
    expect(r.status).toBe(403); // tenant in URL != tenant in token
  });
});

describe("gateway rate limiting", () => {
  // A second gateway with a tiny auth limit (capacity 2), reusing the auth
  // service already booted in beforeAll. Proves brute-force protection on /login.
  const RL_PORT = PORTS.gateway + 50;
  const RL_GW = `http://localhost:${RL_PORT}`;

  beforeAll(async () => {
    await listen(
      createGatewayApp({ authLimit: { capacity: 2, refillPerSec: 0 } }),
      RL_PORT,
    );
  });

  const tryLogin = (email = "carol@acme.test") =>
    fetch(`${RL_GW}/api/auth/login`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email, password: "password" }),
    });

  it("returns 429 with Retry-After once the auth limit is exhausted", async () => {
    expect((await tryLogin()).status).not.toBe(429); // token 1
    expect((await tryLogin()).status).not.toBe(429); // token 2
    const limited = await tryLogin(); // bucket empty
    expect(limited.status).toBe(429);
    expect(limited.headers.get("Retry-After")).toBeTruthy();
    expect(Number(limited.headers.get("X-RateLimit-Remaining"))).toBe(0);
  });
});
