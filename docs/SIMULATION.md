# End-to-End Simulation

This document is a captured, reproducible run of the system. Everything below is **real output**
from the code in this repo — reproduce it with `npm run demo` (scripted) or the curl sequence at
the end (manual).

```bash
npm install
npm run demo
```

## The actors (seed data)

| User | Tenant | Role | Department | Notes |
|---|---|---|---|---|
| alice@acme.test | acme | admin | finance | full access |
| bob@acme.test | acme | manager | engineering | approves eng expenses |
| carol@acme.test | acme | employee | engineering | owns `exp-1` |
| dave@globex.test | globex | admin | ops | **other tenant** |

Seed expenses: `exp-1` (owner carol, engineering), `exp-2` (owner bob, engineering). Passwords
are all `password`.

---

## Scenario walkthrough (captured `npm run demo` output)

```
=== Multi-Tenant Access Control — End-to-End Demo ===

1) RBAC + ABAC (own-resource rule):
  ✓ 200  carol reads her OWN expense exp-1
        {"id":"exp-1","tenantId":"acme","ownerId":"acme-carol","department":"engineering","amount":100,"status":"pending"}
  ✗ 403  carol reads bob's expense exp-2 (denied)
        {"error":"forbidden","reason":"no permission grants read on expense"}

2) ABAC (department-scoped approval):
  ✓ 200  bob approves exp-2 in his dept
        {"id":"exp-2","tenantId":"acme","ownerId":"acme-bob","department":"engineering","amount":250,"status":"approved"}

3) Tenant isolation (404, not 403):
  ✗ 404  globex user reads acme expense
        {"error":"expense not found"}

4) Cross-service + service-to-service auth:
  ✓ 200  alice runs expense summary report
        {"tenantId":"acme","count":2,"total":350,"pending":1}

5) Audit trail (append-only):
  5 decisions recorded for tenant acme

=== Done ===
```

### What each step proves

| Step | Demonstrates | Key requirement |
|---|---|---|
| 1 (allow) | RBAC grant + ABAC own-record condition holds | Fine-grained access control |
| 1 (deny) | Same role denied on someone else's record | Deny-by-default + ABAC |
| 2 | Manager approves only within their department | Contextual ABAC |
| 3 | Cross-tenant access returns **404**, not 403 | Tenant isolation + no enumeration |
| 4 | Reporting mints a scoped service token, calls Expense, aggregates | Cross-service + S2S security |
| 5 | Every decision recorded immutably | Auditability |

---

## Under the hood: a single decision

**Login** (`POST /api/auth/login`) returns a short-lived signed JWT:

```json
{
  "accessToken": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtp...<truncated>",
  "tokenType": "Bearer",
  "expiresIn": 900
}
```

When carol reads `exp-1`, the Expense service PEP calls the PDP. The raw decision
(`POST /authorize`):

```json
// request
{ "tenantId":"acme","userId":"acme-carol","resource":"expense","action":"read",
  "resourceId":"exp-1",
  "resourceAttributes":{"ownerId":"acme-carol","department":"engineering"},
  "requestId":"r-demo-1" }

// response
{ "decision":"allow",
  "reason":"granted by role \"employee\" via permission expense:read" }
```

The PDP records every decision. `GET /tenants/acme/audit?userId=acme-carol` (after an allow and
a deny):

```json
[
  {
    "tenantId": "acme", "userId": "acme-carol",
    "resource": "expense", "action": "read", "resourceId": "exp-1",
    "decision": "allow",
    "reason": "granted by role \"employee\" via permission expense:read",
    "requestId": "r-demo-1",
    "id": "862a324f-306d-457e-9fe5-73e3d6d2e703",
    "timestamp": "2026-06-25T06:54:58.618Z"
  },
  {
    "tenantId": "acme", "userId": "acme-carol",
    "resource": "expense", "action": "read", "resourceId": "exp-2",
    "decision": "deny",
    "reason": "no permission grants read on expense",
    "requestId": "8916a7a4-dbcd-486d-8e81-8eb9d7021509",
    "id": "5bab70ae-88dc-4e79-9b91-43f8b3d0d6fc",
    "timestamp": "2026-06-25T06:54:58.673Z"
  }
]
```

Note the `reason` on the deny — that's what makes "why was I denied?" answerable in support and
audits, and the `requestId` is the correlation id propagated across services.

---

## Reproduce manually with curl

```bash
npm run start   # gateway on :4000, PDP on :4002

# Log in as Carol (employee)
TOKEN=$(curl -s localhost:4000/api/auth/login \
  -H 'content-type: application/json' \
  -d '{"email":"carol@acme.test","password":"password"}' | jq -r .accessToken)

# 1. Read her OWN expense -> 200
curl -s localhost:4000/api/expense/expenses/exp-1 -H "authorization: Bearer $TOKEN"

# 2. Read Bob's expense -> 403 (ABAC own-only)
curl -s localhost:4000/api/expense/expenses/exp-2 -H "authorization: Bearer $TOKEN"

# 3. Cross-tenant: log in as Dave (globex), read an acme expense -> 404
DAVE=$(curl -s localhost:4000/api/auth/login -H 'content-type: application/json' \
  -d '{"email":"dave@globex.test","password":"password"}' | jq -r .accessToken)
curl -s localhost:4000/api/expense/expenses/exp-1 -H "authorization: Bearer $DAVE"

# 4. Cross-service report as admin Alice (service-to-service under the hood) -> 200
ALICE=$(curl -s localhost:4000/api/auth/login -H 'content-type: application/json' \
  -d '{"email":"alice@acme.test","password":"password"}' | jq -r .accessToken)
curl -s localhost:4000/api/reporting/reports/expense-summary -H "authorization: Bearer $ALICE"

# 5. Audit trail (admin-only, scoped to the caller's own tenant)
curl -s localhost:4002/tenants/acme/audit -H "authorization: Bearer $ALICE" | jq

# 6. Dynamic role management — create a role at runtime, no redeploy (requires role:write)
curl -s -X PUT localhost:4002/tenants/acme/roles/acme-auditor \
  -H 'content-type: application/json' -H "authorization: Bearer $ALICE" \
  -d '{"name":"auditor","permissions":[{"resource":"report","action":"read"}]}'
curl -s localhost:4002/tenants/acme/roles -H "authorization: Bearer $ALICE" | jq
```

## Automated proof

`npm test` runs 25 tests across 3 files — pure policy-engine unit tests, the token-bucket
rate-limiter unit tests, and the full end-to-end HTTP flow (unauthenticated/invalid token,
own-record allow, other-record deny, dept approval, cross-tenant 404, cross-service S2S report,
audit recording, dynamic role upsert, **token-audience plane separation**, **PDP admin-endpoint
authorization**, **cross-tenant audit block**, and the gateway 429):

```
 Test Files  3 passed (3)
      Tests  25 passed (25)
```
