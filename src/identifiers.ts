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
 *
 * @throws If the input contains no digits.
 */
export function canonicalPhone(raw: string): string {
  const trimmed = raw.trim();
  const digits = trimmed.replace(/\D/g, "");
  // Without this, "", "abc" and "+" all became the same value and so the same lookup hash.
  if (!digits) throw new Error("not a phone number");
  if (trimmed.startsWith("+")) return `+${digits}`;
  if (digits.length === 10) return `+1${digits}`;
  if (digits.length === 11 && digits.startsWith("1")) return `+${digits}`;
  if (digits.length > 11) return `+${digits}`;
  return `+1${digits}`;
}

/**
 * Lower-cased hostname for a domain typed as `example.com`, `https://Example.com/path`, etc. One trailing dot is
 * dropped, so `example.com.` and `example.com` match.
 *
 * @throws `Error("not a domain")` if the input is empty, contains whitespace or `@` (an email address is not a domain,
 * and `http://user@host` must not silently become `host`), uses a scheme other than http(s), or is not a valid host.
 * The error never includes the input.
 */
export function domainHostname(raw: string): string {
  const lowered = raw.trim().toLowerCase();
  const scheme = /^([a-z][a-z0-9+.-]*):\/\//.exec(lowered)?.[1];
  // "ftp://example.com" used to parse as host "ftp".
  if (scheme !== undefined && scheme !== "http" && scheme !== "https") throw new Error("not a domain");
  const bare = lowered.replace(/^https?:\/\//, "");
  if (!bare || bare.includes("@") || /\s/.test(bare)) throw new Error("not a domain");
  let host: string;
  try {
    host = new URL(`http://${bare}`).hostname;
  } catch {
    // Node's ERR_INVALID_URL carries the raw input; do not let it reach logs.
    throw new Error("not a domain");
  }
  if (host.endsWith(".")) host = host.slice(0, -1);
  if (!host) throw new Error("not a domain");
  return host;
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

/** The first `count` characters, counted in code points so emoji and other astral characters are never split. */
const head = (value: string, count: number): string => Array.from(value).slice(0, count).join("");

/** Fewer digits than this and a phone hint shows none of them. */
const MIN_PHONE_DIGITS_SHOWN = 7;

/**
 * A display hint that reveals just enough to recognize the value without decrypting it,
 * e.g. `"a•••@work.co"` or `"+1 (604) •••-••12"`. Pass the normalized value.
 *
 * Phones in `+1` + 10-digit form keep the NANP layout; other phones show only the last 2 digits (`"+•••-••58"`), and
 * none at all when there are fewer than 7 digits.
 */
export function maskIdentifier(kind: IdentifierKind, normalized: string): string {
  switch (kind) {
    case "email": {
      const at = normalized.lastIndexOf("@");
      if (at < 0) return `${head(normalized, 1)}•••`;
      return `${head(normalized, 1)}•••@${normalized.slice(at + 1)}`;
    }
    case "phone": {
      if (/^\+1\d{10}$/.test(normalized)) {
        return `${normalized.slice(0, 2)} (${normalized.slice(2, 5)}) •••-••${normalized.slice(-2)}`;
      }
      const plus = normalized.startsWith("+") ? "+" : "";
      const digits = normalized.replace(/\D/g, "");
      return digits.length < MIN_PHONE_DIGITS_SHOWN ? `${plus}•••` : `${plus}•••-••${digits.slice(-2)}`;
    }
    case "username":
      return `${head(normalized, 2)}•••`;
    case "domain":
      return normalized;
    case "name":
      return normalized
        .split(" ")
        .map((w) => `${head(w, 1)}•`)
        .join(" ");
    case "address":
      return `${head(normalized, 3)}•••`;
    case "birthdate":
      return `${normalized.slice(0, 4)}-••-••`;
  }
}
