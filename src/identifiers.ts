/** Identifier kinds with built-in normalization and masking rules. */
export type IdentifierKind = "email" | "phone" | "username" | "domain" | "name" | "address" | "birthdate";

/** Overrides for the two rules most apps want to customize. */
export interface NormalizeOptions {
  /** Phone canonicalizer. Default: {@link canonicalPhone} (NANP-style `+1` assumption for 10-digit input). */
  readonly phone?: (raw: string) => string;
  /** Domain canonicalizer. Default: {@link domainHostname}. */
  readonly domain?: (raw: string) => string;
}

/**
 * A small, dependency-free phone canonicalizer: keeps digits, keeps an explicit `+` country code, and assumes `+1` for
 * 10-digit (or `1`-prefixed 11-digit) numbers. Swap in libphonenumber via {@link NormalizeOptions.phone} if you need
 * real international parsing.
 */
export function canonicalPhone(raw: string): string {
  const trimmed = raw.trim();
  const digits = trimmed.replace(/\D/g, "");
  if (trimmed.startsWith("+")) return digits ? `+${digits}` : trimmed;
  if (digits.length === 10) return `+1${digits}`;
  if (digits.length === 11 && digits.startsWith("1")) return `+${digits}`;
  if (digits.length > 11) return `+${digits}`;
  return `+1${digits}`;
}

/**
 * Lower-cased hostname for a domain typed as `example.com`, `https://Example.com/path`, etc.
 *
 * @throws If the input is empty, contains whitespace, or contains `@` (an email address is not a domain, and
 * `http://user@host` must not silently become `host`).
 */
export function domainHostname(raw: string): string {
  const bare = raw
    .trim()
    .toLowerCase()
    .replace(/^https?:\/\//, "");
  if (!bare || bare.includes("@") || /\s/.test(bare)) throw new Error("not a domain");
  return new URL(`http://${bare}`).hostname;
}

/**
 * Canonical form to use before hashing, so `" Alex.Morgan@Mail.com"` and `"alex.morgan@mail.com"` dedupe.
 *
 * - `email`: trimmed, lower-cased
 * - `phone`: {@link canonicalPhone} (or your override)
 * - `username`: leading `@` dropped, lower-cased
 * - `domain`: {@link domainHostname} (or your override)
 * - `name`, `address`: whitespace collapsed (case kept for display; {@link lookupKey} folds case)
 * - `birthdate`: trimmed only (validate the format yourself)
 */
export function normalizeIdentifier(kind: IdentifierKind, raw: string, options: NormalizeOptions = {}): string {
  const v = raw.trim();
  switch (kind) {
    case "email":
      return v.toLowerCase();
    case "phone":
      return (options.phone ?? canonicalPhone)(v);
    case "username":
      return v.replace(/^@/, "").toLowerCase();
    case "domain":
      return (options.domain ?? domainHostname)(v);
    case "name":
    case "address":
      return v.replace(/\s+/g, " ");
    case "birthdate":
      return v;
  }
}

/**
 * The string to feed into a lookup hash for an already-normalized identifier. Free-text kinds (`name`, `address`) are
 * compared case-insensitively; everything else is used as is.
 *
 * @example
 * seal.lookupHash(`identifier:${kind}`, lookupKey(kind, normalizeIdentifier(kind, input)));
 */
export const lookupKey = (kind: IdentifierKind, normalized: string): string =>
  kind === "name" || kind === "address" ? normalized.toLowerCase() : normalized;

/**
 * A display hint that reveals just enough to recognize the value without decrypting it,
 * e.g. `"a•••@work.co"` or `"+1 (604) •••-••12"`. Pass the normalized value.
 */
export function maskIdentifier(kind: IdentifierKind, normalized: string): string {
  switch (kind) {
    case "email": {
      const at = normalized.lastIndexOf("@");
      if (at < 0) return `${normalized.slice(0, 1)}•••`;
      return `${normalized.slice(0, 1)}•••@${normalized.slice(at + 1)}`;
    }
    case "phone":
      return `${normalized.slice(0, 2)} (${normalized.slice(2, 5)}) •••-••${normalized.slice(-2)}`;
    case "username":
      return `${normalized.slice(0, 2)}•••`;
    case "domain":
      return normalized;
    case "name":
      return normalized
        .split(" ")
        .map((w) => `${w.slice(0, 1)}•`)
        .join(" ");
    case "address":
      return `${normalized.slice(0, 3)}•••`;
    case "birthdate":
      return `${normalized.slice(0, 4)}-••-••`;
  }
}
