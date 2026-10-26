/** A versioned set of 32-byte keys plus the version that new writes use. */
export interface Keyring {
  /** Version used for new ciphertexts or new lookup hashes. */
  readonly active: number;
  /** Every key that may still be needed to read existing data, by version (1..65535). */
  readonly keys: ReadonlyMap<number, Buffer>;
}

/** Key material: raw bytes, or a base64 string that decodes to 32 bytes. */
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

function toKey(material: KeyMaterial, version: number, name: string): Buffer {
  const key = typeof material === "string" ? Buffer.from(material, "base64") : Buffer.from(material);
  if (key.length !== KEY_BYTES) throw new Error(`${name}: key ${String(version)} must be ${String(KEY_BYTES)} bytes`);
  return key;
}

function checkVersion(version: number, name: string): void {
  if (!Number.isInteger(version) || version < 1 || version > MAX_VERSION) {
    throw new Error(`${name}: key version must be an integer from 1 to ${String(MAX_VERSION)}`);
  }
}

/**
 * Builds an immutable keyring and validates it up front, so a bad key fails at boot rather than on the first write.
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
  return Object.freeze({ active: options.active, keys });
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
