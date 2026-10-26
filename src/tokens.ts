import { createHash, randomBytes, timingSafeEqual } from "node:crypto";

/**
 * Unkeyed SHA-256. Fine for high-entropy random secrets (session, invite, share-link tokens) where a keyed hash adds
 * nothing. Do not use it for guessable values like emails; use a lookup hash instead.
 */
export const sha256 = (value: string | Uint8Array): Buffer => createHash("sha256").update(value).digest();

/** A URL-safe random token with `bytes` bytes of entropy (default 32). */
export const randomToken = (bytes = 32): string => randomBytes(bytes).toString("base64url");

/** Constant-time comparison that also returns `false` (instead of throwing) when the lengths differ. */
export const safeEqual = (a: Uint8Array, b: Uint8Array): boolean => a.length === b.length && timingSafeEqual(a, b);
