import type { NextFunction, Request, Response } from "express";

/**
 * Token-bucket rate limiter (in-memory, illustrative).
 *
 * Each key owns a bucket of up to `capacity` tokens that refills continuously
 * at `refillPerSec`. A request consumes one token; if none are available it is
 * rejected. This allows controlled bursts (up to `capacity`) while bounding the
 * sustained rate — the model real APIs (Stripe, AWS) use.
 *
 * PRODUCTION NOTE: this state lives in one process's memory, so it is only
 * correct for a single gateway instance. With multiple instances the effective
 * limit multiplies by the instance count. In production the bucket state moves
 * to a shared store (Redis, e.g. CL.THROTTLE / a Lua script) so all instances
 * share one view, the limiter is placed at the edge/managed gateway, and it
 * FAILS OPEN (a limiter outage must not block traffic — the opposite of the
 * authorization path, which fails closed). See DESIGN.md §16.4.
 */
export class TokenBucketLimiter {
  private buckets = new Map<string, { tokens: number; last: number }>();

  constructor(
    public readonly capacity: number,
    private readonly refillPerSec: number,
    /** Injectable clock (ms) so tests are deterministic. */
    private readonly now: () => number = Date.now,
  ) {}

  /** Attempts to consume one token for `key`. Pure of side effects beyond the
   *  bucket map; never throws. */
  tryRemove(key: string): { allowed: boolean; remaining: number; retryAfterSec: number } {
    const t = this.now();
    const bucket = this.buckets.get(key) ?? { tokens: this.capacity, last: t };

    // Refill based on elapsed time since we last touched this bucket.
    const elapsedSec = Math.max(0, (t - bucket.last) / 1000);
    bucket.tokens = Math.min(this.capacity, bucket.tokens + elapsedSec * this.refillPerSec);
    bucket.last = t;

    let allowed = false;
    let retryAfterSec = 0;
    if (bucket.tokens >= 1) {
      bucket.tokens -= 1;
      allowed = true;
    } else if (this.refillPerSec > 0) {
      // Seconds until one whole token is available again.
      retryAfterSec = Math.ceil((1 - bucket.tokens) / this.refillPerSec);
    } else {
      // No refill configured: surface a small fixed backoff rather than Infinity.
      retryAfterSec = 1;
    }

    this.buckets.set(key, bucket);
    return { allowed, remaining: Math.floor(bucket.tokens), retryAfterSec };
  }
}

/**
 * Express middleware applying a limiter, keyed by `keyOf(req)`. If `keyOf`
 * returns undefined the request is not limited (fail open). Sets standard
 * rate-limit headers and responds 429 with Retry-After when exhausted.
 */
export function rateLimit(limiter: TokenBucketLimiter, keyOf: (req: Request) => string | undefined) {
  return (req: Request, res: Response, next: NextFunction) => {
    const key = keyOf(req);
    if (!key) return next();

    const { allowed, remaining, retryAfterSec } = limiter.tryRemove(key);
    res.setHeader("X-RateLimit-Limit", String(limiter.capacity));
    res.setHeader("X-RateLimit-Remaining", String(remaining));

    if (!allowed) {
      res.setHeader("Retry-After", String(retryAfterSec));
      return res.status(429).json({ error: "rate limit exceeded", retryAfterSec });
    }
    return next();
  };
}

/** Best-effort client IP for keying pre-auth limits. */
export function clientIp(req: Request): string {
  return req.ip ?? req.socket.remoteAddress ?? "unknown";
}
