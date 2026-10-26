import { createHmac, randomBytes } from "node:crypto";
import { describe, expect, it } from "vitest";
import { aad, createKeyring, createSeal, keyVersionOf, MIN_ENVELOPE_BYTES, parseKeyring } from "../src/index.js";

const key = () => randomBytes(32);
const k1 = key();
const k2 = key();
const ctx = aad("contacts", "email", "user-1");

describe("aad", () => {
  it("binds table, column and owner", () => {
    expect(aad("t", "c", "o")).toBe("t.c:o");
  });
});

describe("encrypt / decrypt", () => {
  const seal = createSeal({ encryption: createKeyring({ keys: { 1: k1 }, active: 1 }) });

  it("round-trips strings, including empty and non-ASCII", () => {
    for (const s of ["", "hello", "ünïcødé ✓ 🔐", "x".repeat(10_000)]) {
      expect(seal.decrypt(seal.encrypt(s, ctx), ctx)).toBe(s);
    }
  });

  it("round-trips bytes and JSON", () => {
    const bytes = randomBytes(64);
    expect(seal.decryptBytes(seal.encrypt(bytes, ctx), ctx).equals(bytes)).toBe(true);
    const value = { a: 1, b: ["x", null], c: { d: true } };
    expect(seal.decryptJson(seal.encryptJson(value, ctx), ctx)).toEqual(value);
  });

  it("uses a fresh IV for every call", () => {
    expect(seal.encrypt("same", ctx).equals(seal.encrypt("same", ctx))).toBe(false);
  });

  it("writes the documented header", () => {
    const blob = seal.encrypt("abc", ctx);
    expect(blob[0]).toBe(0x01);
    expect(blob.readUInt16BE(1)).toBe(1);
    expect(blob.length).toBe(MIN_ENVELOPE_BYTES + 3);
  });

  it("rejects a different AAD (value moved to another row, column or owner)", () => {
    const blob = seal.encrypt("secret", ctx);
    expect(() => seal.decrypt(blob, aad("contacts", "email", "user-2"))).toThrow();
    expect(() => seal.decrypt(blob, aad("contacts", "phone", "user-1"))).toThrow();
  });

  it("rejects tampering with the ciphertext, tag, IV or header", () => {
    const blob = seal.encrypt("secret", ctx);
    for (const offset of [blob.length - 1, 20, 5]) {
      const bad = Buffer.from(blob);
      bad[offset] = (bad[offset] ?? 0) ^ 0xff;
      expect(() => seal.decrypt(bad, ctx)).toThrow();
    }
    const wrongVersion = Buffer.from(blob);
    wrongVersion.writeUInt16BE(9, 1);
    expect(() => seal.decrypt(wrongVersion, ctx)).toThrow(/key version 9 is not loaded/);
  });

  it("rejects input that is not an envelope", () => {
    expect(() => seal.decrypt(Buffer.alloc(5), ctx)).toThrow(/not a column-seal envelope/);
    const badFormat = seal.encrypt("x", ctx);
    badFormat[0] = 0x02;
    expect(() => keyVersionOf(badFormat)).toThrow(/not a column-seal envelope/);
  });

  it("accepts plain Uint8Array envelopes (e.g. from a driver that does not return Buffer)", () => {
    const blob = new Uint8Array(seal.encrypt("plain", ctx));
    expect(seal.decrypt(blob, ctx)).toBe("plain");
  });
});

describe("key rotation", () => {
  const before = createSeal({ encryption: createKeyring({ keys: { 1: k1 }, active: 1 }) });
  const after = createSeal({ encryption: createKeyring({ keys: { 1: k1, 2: k2 }, active: 2 }) });
  const retired = createSeal({ encryption: createKeyring({ keys: { 2: k2 }, active: 2 }) });

  it("reads old ciphertexts after the active key changes", () => {
    const old = before.encrypt("v1 data", ctx);
    expect(keyVersionOf(old)).toBe(1);
    expect(after.decrypt(old, ctx)).toBe("v1 data");
    expect(keyVersionOf(after.encrypt("new", ctx))).toBe(2);
  });

  it("flags and re-encrypts rows still on an old key", () => {
    const old = before.encrypt("rotate me", ctx);
    expect(after.needsRotation(old)).toBe(true);
    const rotated = after.rotate(old, ctx);
    expect(after.needsRotation(rotated)).toBe(false);
    expect(keyVersionOf(rotated)).toBe(2);
    expect(retired.decrypt(rotated, ctx)).toBe("rotate me");
  });

  it("returns a copy, unchanged, when no rotation is needed", () => {
    const current = after.encrypt("fine", ctx);
    const out = after.rotate(current, ctx);
    expect(out.equals(current)).toBe(true);
    expect(out).not.toBe(current);
  });

  it("refuses to rotate with the wrong AAD", () => {
    expect(() => after.rotate(before.encrypt("x", ctx), "other")).toThrow();
  });

  it("fails clearly once an old key has been removed", () => {
    expect(() => retired.decrypt(before.encrypt("gone", ctx), ctx)).toThrow(/key version 1 is not loaded/);
  });

  it("exposes active versions", () => {
    expect(after.activeKeyVersion).toBe(2);
    expect(after.activeHmacVersion).toBeUndefined();
  });
});

describe("lookup hashes (blind index)", () => {
  const h1 = Buffer.alloc(32, 1);
  const h2 = Buffer.alloc(32, 2);
  const enc = createKeyring({ keys: { 1: k1 }, active: 1 });
  const seal = createSeal({ encryption: enc, hmac: createKeyring({ keys: { 1: h1 }, active: 1 }) });
  const rotating = createSeal({ encryption: enc, hmac: createKeyring({ keys: { 1: h1, 2: h2 }, active: 2 }) });

  it("is deterministic and matches HMAC-SHA256(domain NUL value)", () => {
    const a = seal.lookupHash("identifier:email", "a@example.com");
    expect(a.equals(seal.lookupHash("identifier:email", "a@example.com"))).toBe(true);
    const expected = createHmac("sha256", h1).update("identifier:email\u0000a@example.com").digest();
    expect(a.equals(expected)).toBe(true);
    expect(a.length).toBe(32);
  });

  it("separates domains and values", () => {
    const a = seal.lookupHash("identifier:email", "a@example.com");
    expect(a.equals(seal.lookupHash("newsletter", "a@example.com"))).toBe(false);
    expect(a.equals(seal.lookupHash("identifier:email", "b@example.com"))).toBe(false);
    // the NUL separator keeps ("ab", "c") and ("a", "bc") apart
    expect(seal.lookupHash("ab", "c").equals(seal.lookupHash("a", "bc"))).toBe(false);
  });

  it("depends on the key", () => {
    expect(seal.lookupHash("d", "v").equals(rotating.lookupHash("d", "v"))).toBe(false);
    expect(seal.lookupHash("d", "v").equals(rotating.lookupHash("d", "v", 1))).toBe(true);
  });

  it("returns every version, active first, for lookups during an HMAC rotation", () => {
    const all = rotating.lookupHashes("d", "v");
    expect(all).toHaveLength(2);
    expect(all[0]?.equals(rotating.lookupHash("d", "v", 2))).toBe(true);
    expect(all[1]?.equals(seal.lookupHash("d", "v"))).toBe(true);
    expect(rotating.activeHmacVersion).toBe(2);
  });

  it("throws without an HMAC keyring or for an unknown version", () => {
    const noMac = createSeal({ encryption: enc });
    expect(() => noMac.lookupHash("d", "v")).toThrow(/no hmac keyring/);
    expect(() => noMac.lookupHashes("d", "v")).toThrow(/no hmac keyring/);
    expect(() => seal.lookupHash("d", "v", 7)).toThrow(/hmac key version 7/);
  });
});

describe("keyrings", () => {
  it("accepts base64 strings, bytes and Maps", () => {
    const ring = createKeyring({ keys: new Map([[3, k1.toString("base64")]]), active: 3 });
    expect(ring.keys.get(3)?.equals(k1)).toBe(true);
    expect(
      createKeyring({ keys: { 1: new Uint8Array(k2) }, active: 1 })
        .keys.get(1)
        ?.equals(k2),
    ).toBe(true);
  });

  it("copies key bytes so later mutation of the input has no effect", () => {
    const input = Buffer.from(k1);
    const ring = createKeyring({ keys: { 1: input }, active: 1 });
    input.fill(0);
    expect(ring.keys.get(1)?.equals(k1)).toBe(true);
  });

  it("validates sizes, versions and the active key", () => {
    expect(() => createKeyring({ keys: { 1: randomBytes(16) }, active: 1, name: "APP_KEYS" })).toThrow(
      "APP_KEYS: key 1 must be 32 bytes",
    );
    expect(() => createKeyring({ keys: { 0: k1 }, active: 0 })).toThrow(/integer from 1 to 65535/);
    expect(() => createKeyring({ keys: { 65536: k1 }, active: 65536 })).toThrow(/integer from 1 to 65535/);
    expect(() => createKeyring({ keys: { 1: k1 }, active: 2 })).toThrow(/active key 2 is not in the keyring/);
    expect(() => createKeyring({ keys: {}, active: 1 })).toThrow(/at least one key/);
  });

  it("parses the env-var form", () => {
    const ring = parseKeyring(` 1:${k1.toString("base64")}, 2:${k2.toString("base64")}`, "2", "APP_ENC_KEYS");
    expect(ring.active).toBe(2);
    expect([...ring.keys.keys()]).toEqual([1, 2]);
  });

  it("rejects malformed env values without echoing key material", () => {
    const b64 = k1.toString("base64");
    expect(() => parseKeyring(undefined, "1", "APP_ENC_KEYS")).toThrow("APP_ENC_KEYS is not configured");
    expect(() => parseKeyring(`1:${b64}`, undefined)).toThrow(/not configured/);
    for (const bad of [`x:${b64}`, `1`, `1:${b64}:extra`, `1.5:${b64}`]) {
      try {
        parseKeyring(bad, "1", "K");
        expect.unreachable();
      } catch (e) {
        expect(String(e)).not.toContain(b64);
      }
    }
    expect(() => parseKeyring(`1:${b64},1:${b64}`, "1", "K")).toThrow(/duplicate key version 1/);
    expect(() => parseKeyring(`1:${b64}`, "one", "K")).toThrow(/active version must be a number/);
  });
});
