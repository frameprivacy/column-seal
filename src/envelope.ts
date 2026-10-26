import { createCipheriv, createDecipheriv, createHmac, randomBytes } from "node:crypto";
import type { Keyring } from "./keyring.js";

/** Format byte at offset 0 of every envelope. */
export const FORMAT_VERSION = 0x01;
const IV_LEN = 12;
const TAG_LEN = 16;
const HEADER = 3;
/** Smallest possible envelope: header + IV + tag, with an empty ciphertext. */
export const MIN_ENVELOPE_BYTES = HEADER + IV_LEN + TAG_LEN;

/** Options for {@link createSeal}. */
export interface SealOptions {
  /** Keys for AES-256-GCM encryption. */
  readonly encryption: Keyring;
  /** Separate keys for HMAC lookup hashes. Required only if you call the lookup methods. */
  readonly hmac?: Keyring;
}

/** An encryptor bound to a keyring. Create one at boot and share it. */
export interface Seal {
  /** Version new writes use; store it next to the ciphertext (e.g. an indexed `enc_key_version` column). */
  readonly activeKeyVersion: number;
  /** Version new lookup hashes use, or `undefined` without an HMAC keyring. */
  readonly activeHmacVersion: number | undefined;
  /** Encrypts a string (UTF-8) or bytes into a self-describing envelope. */
  encrypt(plaintext: string | Uint8Array, aad: string): Buffer;
  /** Decrypts an envelope to a UTF-8 string. Throws if the key is unknown, the AAD differs, or the data was altered. */
  decrypt(envelope: Uint8Array, aad: string): string;
  /** Decrypts an envelope to raw bytes. */
  decryptBytes(envelope: Uint8Array, aad: string): Buffer;
  /** `JSON.stringify` then {@link Seal.encrypt}. */
  encryptJson(value: unknown, aad: string): Buffer;
  /** {@link Seal.decrypt} then `JSON.parse`. Returns `unknown`: validate the shape at the call site. */
  decryptJson(envelope: Uint8Array, aad: string): unknown;
  /** True when the envelope was written with a key other than the active one and should be re-encrypted. */
  needsRotation(envelope: Uint8Array): boolean;
  /** Re-encrypts with the active key. Returns the input unchanged when it already uses the active key. */
  rotate(envelope: Uint8Array, aad: string): Buffer;
  /**
   * Keyed HMAC-SHA256 for equality search and dedupe on encrypted values ("blind index").
   * `domain` separates uses, so the same value hashes differently in different contexts. Normalize `value` first.
   */
  lookupHash(domain: string, value: string, version?: number): Buffer;
  /**
   * The lookup hash under every loaded HMAC key, active first. Query with `= ANY(...)` while an HMAC rotation is in
   * progress so rows hashed under the old key are still found.
   */
  lookupHashes(domain: string, value: string): Buffer[];
}

/**
 * Builds the associated-data string `"<table>.<column>:<owner>"`.
 *
 * Binding a ciphertext to where it lives means a value copied into another row, column, or user's record fails to
 * decrypt instead of silently leaking.
 */
export const aad = (table: string, column: string, owner: string): string => `${table}.${column}:${owner}`;

/**
 * Reads the key version from an envelope header without decrypting it.
 *
 * @throws If the input is too short or does not start with the format byte.
 */
export function keyVersionOf(envelope: Uint8Array): number {
  if (envelope.length < MIN_ENVELOPE_BYTES || envelope[0] !== FORMAT_VERSION) {
    throw new Error("not a column-seal envelope");
  }
  return ((envelope[1] ?? 0) << 8) | (envelope[2] ?? 0);
}

/**
 * Creates a {@link Seal}.
 *
 * Envelope layout (works well in a `bytea`/`BLOB` column):
 *
 * | bytes  | field                            |
 * | ------ | -------------------------------- |
 * | 0      | format version (`0x01`)          |
 * | 1..2   | key version, uint16 big-endian   |
 * | 3..14  | 96-bit random IV                 |
 * | 15..30 | 128-bit GCM auth tag             |
 * | 31..   | ciphertext                       |
 *
 * @example
 * const seal = createSeal({ encryption: createKeyring({ keys: { 1: key }, active: 1 }) });
 * const blob = seal.encrypt("+15555550123", aad("contacts", "phone", userId));
 */
export function createSeal(options: SealOptions): Seal {
  const { encryption, hmac } = options;

  const keyFor = (ring: Keyring, version: number, what: string): Buffer => {
    const key = ring.keys.get(version);
    if (!key) throw new Error(`${what} key version ${String(version)} is not loaded`);
    return key;
  };
  const macRing = (): Keyring => {
    if (!hmac) throw new Error("no hmac keyring configured");
    return hmac;
  };

  const encrypt = (plaintext: string | Uint8Array, context: string): Buffer => {
    const key = keyFor(encryption, encryption.active, "encryption");
    const iv = randomBytes(IV_LEN);
    const cipher = createCipheriv("aes-256-gcm", key, iv);
    cipher.setAAD(Buffer.from(context, "utf8"));
    const data = typeof plaintext === "string" ? Buffer.from(plaintext, "utf8") : plaintext;
    const body = Buffer.concat([cipher.update(data), cipher.final()]);
    const header = Buffer.alloc(HEADER);
    header.writeUInt8(FORMAT_VERSION, 0);
    header.writeUInt16BE(encryption.active, 1);
    return Buffer.concat([header, iv, cipher.getAuthTag(), body]);
  };

  const decryptBytes = (envelope: Uint8Array, context: string): Buffer => {
    const key = keyFor(encryption, keyVersionOf(envelope), "encryption");
    const iv = envelope.subarray(HEADER, HEADER + IV_LEN);
    const tag = envelope.subarray(HEADER + IV_LEN, MIN_ENVELOPE_BYTES);
    const decipher = createDecipheriv("aes-256-gcm", key, iv, { authTagLength: TAG_LEN });
    decipher.setAAD(Buffer.from(context, "utf8"));
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(envelope.subarray(MIN_ENVELOPE_BYTES)), decipher.final()]);
  };

  const decrypt = (envelope: Uint8Array, context: string): string => decryptBytes(envelope, context).toString("utf8");

  const lookupHash = (domain: string, value: string, version?: number): Buffer => {
    const ring = macRing();
    const key = keyFor(ring, version ?? ring.active, "hmac");
    return createHmac("sha256", key).update(`${domain}\u0000${value}`, "utf8").digest();
  };

  const needsRotation = (envelope: Uint8Array): boolean => keyVersionOf(envelope) !== encryption.active;

  return Object.freeze({
    activeKeyVersion: encryption.active,
    activeHmacVersion: hmac?.active,
    encrypt,
    decrypt,
    decryptBytes,
    encryptJson: (value: unknown, context: string) => encrypt(JSON.stringify(value), context),
    decryptJson: (envelope: Uint8Array, context: string): unknown => JSON.parse(decrypt(envelope, context)),
    needsRotation,
    rotate: (envelope: Uint8Array, context: string) =>
      needsRotation(envelope) ? encrypt(decryptBytes(envelope, context), context) : Buffer.from(envelope),
    lookupHash,
    lookupHashes: (domain: string, value: string) => {
      const ring = macRing();
      const versions = [ring.active, ...[...ring.keys.keys()].filter((v) => v !== ring.active)];
      return versions.map((v) => lookupHash(domain, value, v));
    },
  });
}
