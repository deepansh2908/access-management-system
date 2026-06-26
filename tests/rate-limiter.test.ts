import { describe, expect, it } from "vitest";
import { TokenBucketLimiter } from "../src/shared/rate-limiter.js";

describe("TokenBucketLimiter", () => {
  it("allows requests up to capacity (burst), then denies", () => {
    const limiter = new TokenBucketLimiter(3, 1, () => 0); // frozen clock
    expect(limiter.tryRemove("k").allowed).toBe(true);
    expect(limiter.tryRemove("k").allowed).toBe(true);
    expect(limiter.tryRemove("k").allowed).toBe(true);
    const denied = limiter.tryRemove("k");
    expect(denied.allowed).toBe(false);
    expect(denied.remaining).toBe(0);
    expect(denied.retryAfterSec).toBeGreaterThan(0);
  });

  it("refills over time at refillPerSec", () => {
    let now = 0;
    const limiter = new TokenBucketLimiter(2, 1, () => now); // 1 token/sec
    expect(limiter.tryRemove("k").allowed).toBe(true);
    expect(limiter.tryRemove("k").allowed).toBe(true);
    expect(limiter.tryRemove("k").allowed).toBe(false); // empty

    now = 1000; // 1 second later -> 1 token refilled
    expect(limiter.tryRemove("k").allowed).toBe(true);
    expect(limiter.tryRemove("k").allowed).toBe(false); // empty again
  });

  it("never refills beyond capacity", () => {
    let now = 0;
    const limiter = new TokenBucketLimiter(2, 100, () => now);
    limiter.tryRemove("k"); // 1 left
    now = 10_000; // huge elapsed time
    // capped at capacity(2): consume twice, third denied
    expect(limiter.tryRemove("k").allowed).toBe(true);
    expect(limiter.tryRemove("k").allowed).toBe(true);
    expect(limiter.tryRemove("k").allowed).toBe(false);
  });

  it("isolates buckets per key (one key cannot starve another)", () => {
    const limiter = new TokenBucketLimiter(1, 1, () => 0);
    expect(limiter.tryRemove("tenantA:user1").allowed).toBe(true);
    expect(limiter.tryRemove("tenantA:user1").allowed).toBe(false); // A exhausted
    expect(limiter.tryRemove("tenantB:user1").allowed).toBe(true); // B unaffected
  });
});
