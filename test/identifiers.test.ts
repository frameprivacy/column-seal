import { describe, expect, it } from "vitest";
import {
  canonicalPhone,
  domainHostname,
  lookupKey,
  maskIdentifier,
  normalizeIdentifier,
  randomToken,
  safeEqual,
  sha256,
} from "../src/index.js";

describe("normalizeIdentifier", () => {
  it("dedupes emails regardless of case and whitespace", () => {
    expect(normalizeIdentifier("email", "  Alex.Morgan@Mail.com ")).toBe("alex.morgan@mail.com");
  });

  it("canonicalizes phones", () => {
    expect(normalizeIdentifier("phone", "(604) 555-0123")).toBe("+16045550123");
    expect(canonicalPhone("1-604-555-0123")).toBe("+16045550123");
    expect(canonicalPhone("+44 20 7946 0958")).toBe("+442079460958");
    expect(canonicalPhone("0044207946095812")).toBe("+0044207946095812");
  });

  it("refuses input with no digits instead of mapping it to a shared value (#12)", () => {
    // "", "abc" and "n/a" all used to become "+1", and "+" stayed "+"
    for (const bad of ["", "   ", "abc", "n/a", "+", "+ ( ) -"]) {
      expect(() => canonicalPhone(bad)).toThrow("not a phone number");
    }
    expect(() => normalizeIdentifier("phone", "none")).toThrow("not a phone number");
    expect(canonicalPhone("+1 604 555 0123")).toBe("+16045550123");
    expect(canonicalPhone("555-0123")).toBe("+15550123"); // short numbers keep the simple +1 rule
  });

  it("strips @ from usernames", () => {
    expect(normalizeIdentifier("username", "@Octo_Cat")).toBe("octo_cat");
  });

  it("extracts hostnames and refuses emails as domains", () => {
    expect(normalizeIdentifier("domain", "HTTPS://Example.COM/path?q=1")).toBe("example.com");
    expect(domainHostname("sub.example.org")).toBe("sub.example.org");
    expect(() => domainHostname("http://user@example.com")).toThrow("not a domain");
    expect(() => domainHostname("   ")).toThrow("not a domain");
    expect(() => domainHostname("exa mple.com")).toThrow("not a domain");
  });

  it("handles other schemes, trailing dots and unparsable hosts (#13)", () => {
    expect(() => domainHostname("ftp://example.com")).toThrow("not a domain"); // used to return "ftp"
    expect(() => domainHostname("git+ssh://example.com")).toThrow("not a domain");
    expect(domainHostname("example.com.")).toBe("example.com");
    expect(domainHostname("https://Example.com./x")).toBe("example.com");
    expect(domainHostname("example.com:8080/a")).toBe("example.com");
    for (const bad of ["mailto:foo", "javascript:alert(1)", "http://", ".", "exa%mple.com"]) {
      let error: unknown;
      try {
        domainHostname(bad);
      } catch (e) {
        error = e;
      }
      expect(String(error)).toBe("Error: not a domain");
      expect((error as { input?: unknown }).input).toBeUndefined();
    }
  });

  it("collapses whitespace in free text but keeps case for display", () => {
    expect(normalizeIdentifier("name", "  Ada   Lovelace ")).toBe("Ada Lovelace");
    expect(normalizeIdentifier("address", "1 Main\tSt")).toBe("1 Main St");
    expect(normalizeIdentifier("birthdate", " 1990-01-02 ")).toBe("1990-01-02");
  });

  it("allows overriding the phone and domain rules", () => {
    const opts = { phone: (s: string) => `tel:${s}`, domain: (s: string) => s.toUpperCase() };
    expect(normalizeIdentifier("phone", " 123 ", opts)).toBe("tel:123");
    expect(normalizeIdentifier("domain", "a.b", opts)).toBe("A.B");
  });
});

describe("lookupKey", () => {
  it("folds case only for free-text kinds", () => {
    expect(lookupKey("name", "Ada Lovelace")).toBe("ada lovelace");
    expect(lookupKey("address", "1 Main St")).toBe("1 main st");
    expect(lookupKey("username", "Mixed")).toBe("Mixed");
  });
});

describe("maskIdentifier", () => {
  it.each([
    ["email", "alex@work.co", "a•••@work.co"],
    ["email", "no-at-sign", "n•••"],
    ["phone", "+16045550112", "+1 (604) •••-••12"],
    ["username", "octocat", "oc•••"],
    ["domain", "example.com", "example.com"],
    ["name", "Ada Lovelace", "A• L•"],
    ["address", "1 Main St", "1 M•••"],
    ["birthdate", "1990-01-02", "1990-••-••"],
  ] as const)("%s %s → %s", (kind, value, masked) => {
    expect(maskIdentifier(kind, value)).toBe(masked);
  });

  it.each([
    // short or non-NANP phones used to show every digit or a wrong country code (#14)
    ["phone", "+44123", "+•••"],
    ["phone", "+442079460958", "+•••-••58"],
    ["phone", "+1555", "+•••"],
    ["phone", "tel:0207946095", "•••-••95"],
    // code points, not UTF-16 units: no lone surrogates in hints (#14)
    ["name", "😀mma Lovelace", "😀• L•"],
    ["email", "🔐x@work.co", "🔐•••@work.co"],
    ["username", "😀😀cat", "😀😀•••"],
    ["address", "🏠🏠🏠 Main", "🏠🏠🏠•••"],
  ] as const)("%s %s → %s", (kind, value, masked) => {
    const hint = maskIdentifier(kind, value);
    expect(hint).toBe(masked);
    expect((hint as string & { isWellFormed(): boolean }).isWellFormed()).toBe(true);
  });
});

describe("tokens", () => {
  it("makes URL-safe random tokens of the requested entropy", () => {
    const t = randomToken();
    expect(t).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(randomToken(16)).toHaveLength(22);
    expect(randomToken()).not.toBe(t);
  });

  it("refuses token sizes that would be empty or guessable (#11)", () => {
    for (const bad of [0, 4, 15, 1.5, -1, Number.NaN, 1025]) {
      expect(() => randomToken(bad)).toThrow(/bytes must be an integer from 16 to 1024/);
    }
    expect(randomToken(1024)).toHaveLength(1366);
  });

  it("hashes with SHA-256", () => {
    expect(sha256("abc").toString("hex")).toBe("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
  });

  it("compares in constant time and tolerates different lengths", () => {
    expect(safeEqual(Buffer.from("abc"), Buffer.from("abc"))).toBe(true);
    expect(safeEqual(Buffer.from("abc"), Buffer.from("abd"))).toBe(false);
    expect(safeEqual(Buffer.from("abc"), Buffer.from("ab"))).toBe(false);
  });
});
