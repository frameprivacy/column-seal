/** A versioned set of 32-byte keys plus the version that new writes use. */
export interface Keyring {
  /** Version used for new ciphertexts or new lookup hashes. */
  readonly active: number;
  /** Every key that may still be needed to read existing data, by version (1..65535). */
  readonly keys: ReadonlyMap<number, Buffer>;
}

/**
 * Key material: raw bytes, or exactly 32 bytes as canonical padded base64 (44 characters ending in `=`, as produced by
 * `randomBytes(32).toString("base64")`). Surrounding whitespace is ignored; anything else is rejected.
 */
export type KeyMaterial = Uint8Array | string;

/** Options for {@link createKeyring}. */
export interface KeyringOptions {
  /** Keys by version. Plain objects (`{ 1: "base64…" }`) and `Map`s are both accepted. */
  readonly keys: Readonly<Record<number, KeyMaterial>> | ReadonlyMap<number, KeyMaterial>;
  /** The version new writes use. Must be one of `keys`. */
  readonly active: number;
  /** Used in error messages, e.g. `"APP_ENC_KEYS"`, so a misconfiguration points at the right setting. */
  readonly name?: string;
}

const KEY_BYTES = 32;
const MAX_VERSION = 0xffff;

/** A `Map` that refuses `set`, `delete` and `clear` once built, so the runtime matches the `ReadonlyMap` type. */
class ReadonlyKeyMap extends Map<number, Buffer> {
  constructor(entries: Iterable<readonly [number, Buffer]>) {
    super();
    for (const [version, key] of entries) super.set(version, key);
  }
  override set(): this {
    throw new TypeError("keyring is read-only");
  }
  override delete(): boolean {
    throw new TypeError("keyring is read-only");
  }
  override clear(): void {
    throw new TypeError("keyring is read-only");
  }
}

/** Padded base64 for exactly 32 bytes: 43 characters and one `=`. */
const BASE64_KEY = /^[A-Za-z0-9+/]{43}=$/;

/**
 * Strict base64 decoding. `Buffer.from(s, "base64")` skips unknown characters, also accepts base64url and stops at the
 * first `=`, so a passphrase or a mangled value could otherwise be accepted as a key. Only canonical padded base64
 * (what `randomBytes(32).toString("base64")` produces) is accepted.
 */
function decodeKey(material: string, version: number, name: string): Buffer {
  const text = material.trim();
  const bytes = BASE64_KEY.test(text) ? Buffer.from(text, "base64") : undefined;
  if (bytes?.toString("base64") !== text) {
    bytes?.fill(0);
    throw new Error(`${name}: key ${String(version)} must be ${String(KEY_BYTES)} bytes of padded base64`);
  }
  return bytes;
}

/**
 * Copies key material into its own `Buffer.alloc` allocation. `Buffer.from` serves small sizes from Node's shared
 * 8 KiB pool, which would put key bytes in the same memory as unrelated Buffers.
 */
function toKey(material: KeyMaterial, version: number, name: string): Buffer {
  const bytes = typeof material === "string" ? decodeKey(material, version, name) : material;
  try {
    if (bytes.length !== KEY_BYTES) {
      throw new Error(`${name}: key ${String(version)} must be ${String(KEY_BYTES)} bytes`);
    }
    const key = Buffer.alloc(KEY_BYTES);
    key.set(bytes);
    return key;
  } finally {
    // The decoded temporary lives in the shared pool: wipe it. Caller-owned bytes are left alone.
    if (typeof material === "string") bytes.fill(0);
  }
}

function checkVersion(version: unknown, name: string): number {
  if (typeof version !== "number" || !Number.isInteger(version) || version < 1 || version > MAX_VERSION) {
    throw new Error(`${name}: key version must be an integer from 1 to ${String(MAX_VERSION)}`);
  }
  return version;
}

/**
 * Builds an immutable keyring and validates it up front, so a bad key fails at boot rather than on the first write.
 * The returned `keys` map throws on `set`, `delete` and `clear`.
 *
 * Keys are always supplied by the caller (environment, KMS, secret manager); this library never stores or generates
 * long-lived keys.
 *
 * @example
 * const ring = createKeyring({ keys: { 1: process.env.OLD_KEY!, 2: process.env.NEW_KEY! }, active: 2 });
 */
export function createKeyring(options: KeyringOptions): Keyring {
  const name = options.name ?? "keyring";
  const entries: [number, KeyMaterial][] =
    options.keys instanceof Map
      ? [...(options.keys as ReadonlyMap<number, KeyMaterial>)]
      : Object.entries(options.keys as Readonly<Record<number, KeyMaterial>>).map(([v, k]): [number, KeyMaterial] => [
          Number(v),
          k,
        ]);
  if (entries.length === 0) throw new Error(`${name}: at least one key is required`);
  const keys = new Map<number, Buffer>();
  for (const [version, material] of entries) {
    checkVersion(version, name);
    keys.set(version, toKey(material, version, name));
  }
  if (!keys.has(options.active)) throw new Error(`${name}: active key ${String(options.active)} is not in the keyring`);
  return Object.freeze({ active: options.active, keys: new ReadonlyKeyMap(keys) });
}

/**
 * Validates any object shaped like a {@link Keyring} (including hand-built ones) and returns a private copy, so later
 * changes to the input cannot affect the caller. Used by `createSeal`.
 *
 * @internal
 */
export function snapshotKeyring(ring: Keyring, name: string): Keyring {
  // Checked as `unknown`: the input may come from plain JavaScript or a hand-built object.
  const input: unknown = ring;
  if (typeof input !== "object" || input === null) throw new Error(`${name}: not a keyring`);
  const { active, keys: source } = input as { active?: unknown; keys?: unknown };
  if (!(source instanceof Map)) throw new Error(`${name}: not a keyring`);
  const keys = new Map<number, Buffer>();
  for (const [version, key] of source as Map<unknown, unknown>) {
    const v = checkVersion(version, name);
    if (!(key instanceof Uint8Array)) throw new Error(`${name}: key ${String(v)} must be bytes`);
    keys.set(v, toKey(key, v, name));
  }
  if (keys.size === 0) throw new Error(`${name}: at least one key is required`);
  const a = checkVersion(active, name);
  if (!keys.has(a)) throw new Error(`${name}: active key ${String(a)} is not in the keyring`);
  return Object.freeze({ active: a, keys: new ReadonlyKeyMap(keys) });
}

/**
 * Parses the common environment-variable form `"1:<base64>,2:<base64>"` plus an active version string.
 *
 * @param list - Comma-separated `version:base64` pairs.
 * @param active - The active version, as a string (it usually comes straight from the environment).
 * @param name - Setting name used in error messages.
 * @throws If either value is missing or any entry is malformed.
 *
 * @example
 * const ring = parseKeyring(process.env.APP_ENC_KEYS, process.env.APP_ENC_ACTIVE_KEY, "APP_ENC_KEYS");
 */
export function parseKeyring(list: string | undefined, active: string | undefined, name = "keyring"): Keyring {
  if (!list || !active) throw new Error(`${name} is not configured`);
  const keys = new Map<number, string>();
  for (const part of list.split(",")) {
    const [v, b64, extra] = part.trim().split(":");
    if (!v || !b64 || extra !== undefined || !/^\d+$/.test(v)) throw new Error(`${name}: bad entry`);
    const version = Number(v);
    if (keys.has(version)) throw new Error(`${name}: duplicate key version ${v}`);
    keys.set(version, b64);
  }
  if (!/^\d+$/.test(active.trim())) throw new Error(`${name}: active version must be a number`);
  return createKeyring({ keys, active: Number(active), name });
}
