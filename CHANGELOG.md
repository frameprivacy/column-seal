# Changelog

All notable changes to this project are documented here. The envelope format is unchanged (`0x01`): every
ciphertext written by an earlier version still decrypts.

## Unreleased

### Fixed

- `aad()` now throws for an empty table or column, a table containing `.` or `:`, or a column containing `:`. Those
  inputs could produce the same context string for different locations (#3). Output for valid names is unchanged.
