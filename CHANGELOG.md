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
