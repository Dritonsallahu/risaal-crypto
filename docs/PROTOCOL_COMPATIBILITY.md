# Protocol Versioning & Compatibility Policy

This document defines versioning and compatibility rules for wire/protocol behavior.

## Version Sources

- Protocol specification version: `PROTOCOL.md`.
- Package/API version: `pubspec.yaml` semantic version.

## Compatibility Rules

1. **Patch release (`x.y.Z`)**
   - No wire-format breaking changes.
   - Security fixes are allowed if backward-compatible at protocol level.

2. **Minor release (`x.Y.z`)**
   - Backward-compatible protocol extensions allowed.
   - New fields must be optional and safely ignored by older parsers.

3. **Major release (`X.y.z`)**
   - Breaking wire/protocol changes allowed only with migration notes.
   - Must include explicit compatibility matrix update.

## Mandatory Requirements for Protocol Changes

- Update `PROTOCOL.md` version/status section.
- Add or update test vectors for changed behavior.
- Add changelog entry with `[SECURITY]` prefix if security-relevant.
- Document downgrade/interop implications in PR description.

## Supported Compatibility Window

- Current protocol version: fully supported.
- Previous protocol version: security patches and migration support when feasible.
- Older versions: no guarantee.

## Interoperability Validation

For protocol changes, maintain deterministic vectors to ensure consistent behavior across implementations.

Minimum validation requirement:
- Encrypt/decrypt, signature verification, replay rejection, and downgrade checks must remain deterministic for defined vectors.
