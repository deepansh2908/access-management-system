# Multi-Tenant Access Control Across Microservices

A reference implementation **and** design for an enterprise-grade access-control system for a
multi-tenant, microservices-based SaaS platform.

## 📚 Documentation map

| Document | What's in it |
|---|---|
| **[docs/DESIGN.md](docs/DESIGN.md)** | The main design document: problem, assumptions, requirements, **HLD**, **LLD**, access model, tenant isolation, authn/authz flows, S2S security, APIs, data models, scalability, security/compliance, operations, **tradeoffs & alternatives**, **future roadmap**. All diagrams. |
| **[docs/CODE_WALKTHROUGH.md](docs/CODE_WALKTHROUGH.md)** | Every file explained — what it does, why it exists, key functions. |
| **[docs/SIMULATION.md](docs/SIMULATION.md)** | A full end-to-end simulation with real, captured output for every scenario. |
| **[docs/SUBMISSION_CHECKLIST.md](docs/SUBMISSION_CHECKLIST.md)** | Maps every required submission item to where it's satisfied. |

> Start with **DESIGN.md**. This repo implements a **focused vertical slice** that proves the
> design end-to-end; the same patterns generalize to every other service in the platform
> (Payroll, Invoice, Workflow, Notification).

## What's implemented

| Component | Role | Path |
|---|---|---|
| **Auth Service** | Authenticates users; issues short-lived RS256 JWTs; publishes JWKS; issues service tokens (client-credentials) | `src/auth-service` |
| **Authorization Service (PDP)** | Central Policy Decision Point — evaluates RBAC + ABAC, writes the audit log, dynamic role management | `src/pdp` |
| **API Gateway (PEP #1)** | Single entry point; authenticates at the edge and routes | `src/gateway` |
| **Expense Service** | Sample domain service; fine-grained ABAC (own-resource, dept-scoped) | `src/services/expense` |
| **Reporting Service** | Cross-service + service-to-service auth | `src/services/reporting` |
| **PEP middleware** | `authenticate` + `enforce`, in front of every protected endpoint | `src/shared/pep.ts` |
| **Policy engine** | Pure, deny-by-default RBAC+ABAC evaluator | `src/pdp/policy-engine.ts` |

## Concepts demonstrated

- **Authentication** — password login → signed short-lived JWT with tenant + role claims; JWKS-based verification (no shared secret).
- **Authorization** — central PDP, enforced by PEPs at the gateway and in each service (defense in depth), **deny by default**, every decision audited.
- **Fine-grained access control** — hybrid **RBAC + ABAC**: roles for coarse grain; attribute conditions (*own records only*, *approve only within your department*) for fine grain.
- **Tenant isolation** — every data access scoped by `tenantId`; cross-tenant access is invisible (**404, not 403**).
- **Service-to-service security** — reporting obtains a scoped, **least-privilege** service token and is authorized like any other principal (no implicit trust).
- **Dynamic role/permission management** — roles are data, editable at runtime via the PDP API (no redeploy).
- **Auditability** — append-only log of every decision with reason + correlation id.
- **Rate limiting** — token-bucket at the gateway, two tiers (IP-keyed on auth endpoints, `tenantId:userId`-keyed elsewhere); `429` + `Retry-After`, fails open (demo-grade; see DESIGN §16.4).

## Run it

Requires Node 20+.

```bash
npm install
npm test        # 25 tests: policy-engine + rate-limiter unit tests + full end-to-end flow
npm run demo    # boots everything in-process and walks through every scenario
```

Run the full system (gateway on :4000):

```bash
npm run start            # all services in one process
# each service separately: npm run auth | pdp | gateway | expense | reporting
# optional containers:     docker compose up --build
```

### Try it with curl

```bash
# 1. Log in (employee Carol)
TOKEN=$(curl -s localhost:4000/api/auth/login \
  -H 'content-type: application/json' \
  -d '{"email":"carol@acme.test","password":"password"}' | jq -r .accessToken)

# 2. Read her OWN expense -> 200
curl -s localhost:4000/api/expense/expenses/exp-1 -H "authorization: Bearer $TOKEN"

# 3. Read someone else's expense -> 403 (ABAC)
curl -s localhost:4000/api/expense/expenses/exp-2 -H "authorization: Bearer $TOKEN"

# 4. Inspect the audit trail (admin-only; scoped to the caller's tenant)
ADMIN=$(curl -s localhost:4000/api/auth/login -H 'content-type: application/json' \
  -d '{"email":"alice@acme.test","password":"password"}' | jq -r .accessToken)
curl -s localhost:4002/tenants/acme/audit -H "authorization: Bearer $ADMIN" | jq
```

## Seed data

Two tenants prove isolation (all passwords `password`, see `src/data/seed.ts`):

- **acme** — `alice` (admin), `bob` (manager, engineering), `carol` (employee, engineering)
- **globex** — `dave` (admin)

## Deliberate simplifications (production notes in DESIGN.md §11–13)

- In-memory store behind **repository interfaces** → swap for Postgres + Row-Level Security.
- Signing keys generated at startup → KMS/HSM with rotation.
- Plaintext seed passwords → bcrypt/argon2 + real user store.
- Single demo service secret → per-service rotated credentials + mTLS.
- PEP decision cache + policy-bundle distribution → **designed**, not built.
- In-memory rate limiter (per-process) → Redis-backed at the edge, fail-open (see DESIGN §16.4).

These are isolated behind interfaces precisely so the swaps are mechanical — see the design doc.
