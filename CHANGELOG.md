# Changelog

All notable changes to this project are documented here. The envelope format is unchanged (`0x01`): every
ciphertext written by an earlier version still decrypts.

## Unreleased

### Fixed

- `aad()` now throws for an empty table or column, a table containing `.` or `:`, or a column containing `:`. Those
  inputs could produce the same context string for different locations (#3). Output for valid names is unchanged.
- Keyrings are now read-only at runtime: `keys.set`, `keys.delete` and `keys.clear` throw, matching the
  `ReadonlyMap` type (#4).
- `createSeal` validates both keyrings (including hand-built ones) and keeps a private copy of the keys, so a bad
  keyring fails at construction and later changes to the input keyring have no effect (#4).
- Key bytes are copied into dedicated allocations instead of Node's shared `Buffer` pool, and the temporary decoded
  from a base64 string is wiped (#5).
- `createKeyring` rejects object keys that are not canonical decimal integers (`"01"`, `"1.0"`, `" 1"`, `"1e3"`), which
  used to alias another version and silently drop a key (#7).
- `lookupHash` and `lookupHashes` throw for an empty domain or a domain containing NUL, which could make two different
  (domain, value) pairs hash the same (#8). Hashes for valid domains are unchanged.
- Strings with lone surrogates now throw a `TypeError` in `encrypt`, `aad`, AAD contexts and `lookupHash`. They used
  to be silently replaced with U+FFFD, so the value changed on decrypt and different strings could bind or hash the
  same (#9).
- `decrypt` decodes strictly and throws when the plaintext is not valid UTF-8 (for example bytes written with
  `encrypt(bytes)`), instead of returning replacement characters. `decryptBytes` is unchanged (#9).
- `encryptJson` throws `TypeError("encryptJson: value is not JSON-serializable")` for `undefined`, functions and
  symbols, instead of an unrelated internal `ERR_INVALID_ARG_TYPE` from `node:crypto` (#10).
- `canonicalPhone` (and `normalizeIdentifier("phone", ...)`) throws `"not a phone number"` for input with no digits.
  `""`, `"abc"` and `"n/a"` all used to become `"+1"` (and `"+"` stayed `"+"`), so unrelated invalid input shared one
  lookup hash (#12). Numbers with digits canonicalize exactly as before.

### Changed

- Key strings are decoded strictly: they must be exactly 32 bytes as canonical padded base64 (44 characters ending in
  `=`, as `randomBytes(32).toString("base64")` produces), with surrounding whitespace ignored. Previously invalid
  characters were skipped, trailing data was ignored and base64url was accepted, so a 43-character passphrase or a
  mangled value could load as a key (#6). Keys generated as the README shows are unaffected. To migrate a base64url
  key, re-encode the same bytes: `Buffer.from(key, "base64url").toString("base64")`.
- `randomToken(bytes)` requires an integer from 16 (128 bits) to 1024 and throws a `RangeError` otherwise.
  `randomToken(0)` used to return an empty string. The default (32) is unchanged (#11).
