/** Service ports and inter-service URLs. Overridable via env for containers. */
export const PORTS = {
  auth: Number(process.env.AUTH_PORT ?? 4001),
  pdp: Number(process.env.PDP_PORT ?? 4002),
  gateway: Number(process.env.GATEWAY_PORT ?? 4000),
  expense: Number(process.env.EXPENSE_PORT ?? 4003),
  reporting: Number(process.env.REPORTING_PORT ?? 4004),
};

export const URLS = {
  auth: process.env.AUTH_URL ?? `http://localhost:${PORTS.auth}`,
  pdp: process.env.PDP_URL ?? `http://localhost:${PORTS.pdp}`,
  expense: process.env.EXPENSE_URL ?? `http://localhost:${PORTS.expense}`,
  reporting: process.env.REPORTING_URL ?? `http://localhost:${PORTS.reporting}`,
};

/** Access-token lifetime. Short by design — bounds the blast radius of a
 *  leaked token and is the baseline revocation mechanism (see DESIGN.md §9). */
export const ACCESS_TTL_SECONDS = 15 * 60;

/**
 * Gateway rate limits (token bucket). `capacity` = max burst; `refillPerSec` =
 * sustained rate. Two tiers (see DESIGN.md §16.4):
 *  - `auth`: tight, keyed by client IP — blunts credential brute-forcing on
 *            /login and /token (no token exists yet to key on).
 *  - `authenticated`: generous, keyed by tenantId:userId — noisy-neighbor
 *            fairness so one tenant/user can't starve others.
 * Defaults are generous enough for the demo + tests; override via env.
 */
export const RATE_LIMITS = {
  auth: {
    capacity: Number(process.env.RL_AUTH_CAPACITY ?? 30),
    refillPerSec: Number(process.env.RL_AUTH_REFILL ?? 0.5), // ~30/min sustained
  },
  authenticated: {
    capacity: Number(process.env.RL_USER_CAPACITY ?? 120),
    refillPerSec: Number(process.env.RL_USER_REFILL ?? 2), // ~120/min sustained
  },
};
