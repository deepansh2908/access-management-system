import { z } from "zod";

/**
 * Zod schemas for every value that crosses a trust boundary (HTTP request
 * bodies, inter-service responses, decoded token claims). Parsing with these
 * gives runtime validation AND a precise inferred type, so callers never need
 * an `as` cast on untrusted data. The domain types in types.ts are derived from
 * these where the shape is shared, keeping one source of truth.
 */

// --- ABAC primitives ---
export const clauseSchema = z.object({
  attribute: z.string(),
  op: z.enum(["eq", "neq", "in", "lte", "gte"]),
  value: z.union([
    z.string(),
    z.number(),
    z.boolean(),
    z.array(z.union([z.string(), z.number()])),
  ]),
});

export const conditionSchema = z.object({ allOf: z.array(clauseSchema) });

export const permissionSchema = z.object({
  resource: z.string(),
  action: z.string(),
  condition: conditionSchema.optional(),
});

const attributeValue = z.union([z.string(), z.number(), z.boolean()]);

// --- Authorization request/response (PEP <-> PDP) ---
export const authorizationRequestSchema = z.object({
  tenantId: z.string().min(1),
  userId: z.string().min(1),
  resource: z.string().min(1),
  action: z.string().min(1),
  resourceId: z.string().optional(),
  resourceAttributes: z.record(z.string(), attributeValue).optional(),
  requestId: z.string().min(1),
});

export const authorizationResponseSchema = z.object({
  decision: z.enum(["allow", "deny"]),
  reason: z.string(),
});

// --- Token claims (decoded JWT payload) ---
export const accessTokenClaimsSchema = z.object({
  sub: z.string(),
  tenantId: z.string(),
  roles: z.array(z.string()),
  email: z.string(),
  type: z.enum(["user", "service"]),
});

// --- HTTP request bodies ---
export const loginSchema = z.object({
  email: z.string().min(1),
  password: z.string().min(1),
});

export const serviceTokenSchema = z.object({
  clientId: z.string().min(1),
  clientSecret: z.string().min(1),
  tenantId: z.string().min(1),
});

export const roleUpsertSchema = z.object({
  name: z.string().optional(),
  permissions: z.array(permissionSchema).default([]),
});

export const createExpenseSchema = z.object({
  department: z.string().default("general"),
  amount: z.number().nonnegative().default(0),
});

// --- External/inter-service responses ---
export const tokenResponseSchema = z.object({
  accessToken: z.string(),
  tokenType: z.string().optional(),
  expiresIn: z.number().optional(),
});

export const internalExpensesSchema = z.array(
  z.object({ amount: z.number(), status: z.string() }),
);

/** A JWK is an object of crypto parameters; we only require `kid` and pass the
 *  rest through to Node's createPublicKey. */
export const jwksSchema = z.object({
  keys: z.array(z.looseObject({ kid: z.string() })),
});
