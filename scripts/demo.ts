/**
 * Live end-to-end walkthrough. Boots all services in-process then exercises
 * every scenario through the gateway, printing each decision. Run: npm run demo
 */
import { seed } from "../src/data/seed.js";
import { seededExpenseRepository } from "../src/data/expense-store.js";
import { PORTS, URLS } from "../src/shared/config.js";
import { createAuthApp } from "../src/auth-service/app.js";
import { createPdpApp } from "../src/pdp/app.js";
import { createGatewayApp } from "../src/gateway/app.js";
import { createExpenseApp } from "../src/services/expense/app.js";
import { createReportingApp } from "../src/services/reporting/app.js";

const GW = `http://localhost:${PORTS.gateway}`;
const store = seed();
const servers = [
  createAuthApp(store).listen(PORTS.auth),
  createPdpApp(store).listen(PORTS.pdp),
  createExpenseApp(seededExpenseRepository()).listen(PORTS.expense),
  createReportingApp().listen(PORTS.reporting),
  createGatewayApp().listen(PORTS.gateway),
];

async function login(email: string): Promise<string> {
  const r = await fetch(`${GW}/api/auth/login`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ email, password: "password" }),
  });
  return ((await r.json()) as { accessToken: string }).accessToken;
}

async function call(label: string, path: string, token: string, method = "GET") {
  const r = await fetch(`${GW}${path}`, { method, headers: { authorization: `Bearer ${token}` } });
  const tag = r.status < 400 ? "✓" : "✗";
  console.log(`  ${tag} ${r.status}  ${label}\n        ${await r.text()}`);
}

async function main() {
  await new Promise((r) => setTimeout(r, 300));
  console.log("\n=== Multi-Tenant Access Control — End-to-End Demo ===\n");

  const carol = await login("carol@acme.test"); // employee, engineering
  const bob = await login("bob@acme.test"); // manager, engineering
  const alice = await login("alice@acme.test"); // admin
  const dave = await login("dave@globex.test"); // other tenant

  console.log("1) RBAC + ABAC (own-resource rule):");
  await call("carol reads her OWN expense exp-1", "/api/expense/expenses/exp-1", carol);
  await call("carol reads bob's expense exp-2 (denied)", "/api/expense/expenses/exp-2", carol);

  console.log("\n2) ABAC (department-scoped approval):");
  await call("bob approves exp-2 in his dept", "/api/expense/expenses/exp-2/approve", bob, "POST");

  console.log("\n3) Tenant isolation (404, not 403):");
  await call("globex user reads acme expense", "/api/expense/expenses/exp-1", dave);

  console.log("\n4) Cross-service + service-to-service auth:");
  await call("alice runs expense summary report", "/api/reporting/reports/expense-summary", alice);

  console.log("\n5) Audit trail (append-only, admin-only):");
  const audit = (await (
    await fetch(`${URLS.pdp}/tenants/acme/audit`, { headers: { authorization: `Bearer ${alice}` } })
  ).json()) as unknown[];
  console.log(`  ${audit.length} decisions recorded for tenant acme`);

  console.log("\n=== Done ===\n");
  for (const s of servers) s.close();
}

main();
