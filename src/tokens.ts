import { createHash, randomBytes, timingSafeEqual } from "node:crypto";

/**
 * Unkeyed SHA-256. Fine for high-entropy random secrets (session, invite, share-link tokens) where a keyed hash adds
 * nothing. Do not use it for guessable values like emails; use a lookup hash instead.
 */
export const sha256 = (value: string | Uint8Array): Buffer => createHash("sha256").update(value).digest();

const MIN_TOKEN_BYTES = 16;
const MAX_TOKEN_BYTES = 1024;

/**
 * A URL-safe random token with `bytes` bytes of entropy (default 32).
 *
 * @throws RangeError unless `bytes` is an integer from 16 (128 bits) to 1024, so a bad argument can never produce an
 * empty or guessable token.
 */
export const randomToken = (bytes = 32): string => {
  if (!Number.isInteger(bytes) || bytes < MIN_TOKEN_BYTES || bytes > MAX_TOKEN_BYTES) {
    throw new RangeError(
      `randomToken: bytes must be an integer from ${String(MIN_TOKEN_BYTES)} to ${String(MAX_TOKEN_BYTES)}`,
    );
  }
  return randomBytes(bytes).toString("base64url");
};

/** Constant-time comparison that also returns `false` (instead of throwing) when the lengths differ. */
export const safeEqual = (a: Uint8Array, b: Uint8Array): boolean => a.length === b.length && timingSafeEqual(a, b);
