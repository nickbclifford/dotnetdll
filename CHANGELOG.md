# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

While the crate is pre-1.0, the public API may change between minor versions.

## [Unreleased]

## [0.3.0] - 2026-06-23

### Added

- `ReadOptions::lazy_attributes`: defer distribution of custom attributes during
  parsing, resolving them on demand via `Resolution::type_attributes`,
  `Resolution::method_attributes`, `Resolution::field_attributes`, and
  `Resolution::assembly_attributes`.
- `ReadOptions::lazy_property_signatures`: defer property-signature decoding until
  first access via `Resolution::property_signature`.
- Structured error hierarchy: `ParseError`, `ValidityError`, and `ResolveError`,
  surfaced through the new `DLLError::Parse`, `DLLError::Validity`, and
  `DLLError::Resolve` variants.
- `stage-timing` cargo feature and a decode-stage timing benchmark.

### Changed

- Parallelized the decode stages with rayon, including parallel member-reference
  decoding. Parallel sites use a `with_min_len(256)` threshold to avoid
  overhead on small inputs.
- Replaced the lazy-attribute `OnceLock` caches with sparse `FxHashMap`s built at
  construction, and added O(1) reverse maps for method and field attributes.

### Removed

- **Breaking:** removed the legacy `DLLError::CLI(scroll::Error)` and
  `DLLError::Other(&'static str)` variants in favor of the structured categories
  above. See the migration guide in the `DLLError` documentation for the mapping
  from the old variants. Code that only stringifies errors needs no changes.

[Unreleased]: https://github.com/nickbclifford/dotnetdll/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/nickbclifford/dotnetdll/compare/v0.2.0...v0.3.0
