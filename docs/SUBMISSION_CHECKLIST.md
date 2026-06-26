# Submission Checklist

Maps every item the assignment asks for to exactly where it is satisfied in this submission.

## "Please submit"

| Required item | Status | Where |
|---|---|---|
| **Executable codebase (GitHub link)** | ✅ | This repo. Runs via `npm run start` / `npm run demo` / `docker compose up`. 25 tests pass (`npm test`). |
| **A design document (PDF/Markdown/Slides)** | ✅ | [docs/DESIGN.md](DESIGN.md) (Markdown; exports cleanly to PDF). |
| **Architecture diagrams** | ✅ | DESIGN.md §4.1 (component diagram), plus the cache-flow diagram §11. |
| **Flow / sequence diagrams where relevant** | ✅ | DESIGN.md §7.1 (login + authorized request), §8 (service-to-service). |
| **API examples** | ✅ | DESIGN.md §10, [SIMULATION.md](SIMULATION.md) (captured requests/responses), README curl block. |
| **Schema diagrams** | ✅ | DESIGN.md §5.2 (entity ERD), §6.1 (isolation spectrum). |

## "Please ensure"

| Requirement | Status | Where |
|---|---|---|
| **Assumptions are clearly documented** | ✅ | DESIGN.md §2 (assumptions table A1–A7). |
| **Tradeoffs are properly explained** | ✅ | DESIGN.md §14 (tradeoffs & alternatives table) + per-section rationale. |
| **Decisions are well justified** | ✅ | Each decision states chosen + alternative + why (§5, §6, §7, §8, §14). |

## "What we expect you to design and document"

| Expected | Status | Where |
|---|---|---|
| Functional & non-functional requirements | ✅ | DESIGN.md §3 |
| High-level architecture | ✅ | DESIGN.md §4 (HLD) |
| Authentication & authorization flow | ✅ | DESIGN.md §7 + sequence diagrams |
| Multi-tenant isolation strategy | ✅ | DESIGN.md §6 |
| Access control model | ✅ | DESIGN.md §5 (RBAC+ABAC, ERD, algorithm) |
| Service-to-service security approach | ✅ | DESIGN.md §8 |
| APIs and data models | ✅ | DESIGN.md §10 + §5.2 |
| Scalability and reliability considerations | ✅ | DESIGN.md §11 |
| Security and compliance considerations | ✅ | DESIGN.md §12 |
| Operational concerns (monitoring, auditing, debugging) | ✅ | DESIGN.md §13 |

## "We are interested in"

| Signal | Where it shows up |
|---|---|
| Depth of technical understanding | LLD (§9), policy engine, JWKS/token design |
| Product & domain thinking | Tenant tiers (§6), dynamic roles, future roadmap (§15) |
| Security awareness | §12, deny-by-default, 404-not-403, least-privilege S2S, revocation strategy |
| Distributed systems knowledge | PDP/PEP split, caching/fail-closed (§11), stateless JWT, partitioning |
| Design clarity and reasoning | Tradeoffs table (§14), worked examples, design→code map |

## Extra (beyond the brief)

| Item | Where |
|---|---|
| Working reference implementation proving the design | `src/`, `npm run demo` |
| Automated tests (unit + integration) | `tests/`, 16 passing |
| File-by-file code walkthrough | [CODE_WALKTHROUGH.md](CODE_WALKTHROUGH.md) |
| Captured end-to-end simulation with real output | [SIMULATION.md](SIMULATION.md) |
| Persistence-swap seam (in-memory → Postgres+RLS) | `src/data/repositories.ts` |
