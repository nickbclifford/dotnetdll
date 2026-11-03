# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

While the crate is pre-1.0, the public API may change between minor versions.

## [Unreleased]

## [0.4.0] - 2026-11-02

This release adds opt-in metadata heap ownership for faster parsing under Miri
Tree Borrows. Native parsing continues to borrow heap values by default, and
resolved field types and input lifetimes are unchanged. See the
[0.4 migration guide](docs/migration-0.4.md) for the options API change.

### Added

- `ReadOptions::own_heap_values` and `with_own_heap_values`: optionally copy retained
  metadata heap strings and blobs into existing `Cow::Owned` fields, reducing
  alias-tracking costs under Miri Tree Borrows. Zero-copy parsing remains the default;
  lazy attribute accessors honor the selected ownership policy.
- Builder methods for all `ReadOptions` flags and a const `ReadOptions::new()` constructor.
- Self-contained ownership and deferred-body regression tests, with dedicated
  Rust 1.85.1 and pinned Tree Borrows CI jobs.

### Changed

- Store deferred method bodies as validated ranges into one shared input slice,
  reducing live input borrows without copying IL or changing public lifetimes.
- **Breaking:** `ReadOptions` is now `#[non_exhaustive]`. Replace downstream struct
  literals (including those with `..Default::default()`) with `ReadOptions::default()`
  followed by builder calls or field assignments. Const configurations can use
  `ReadOptions::new()` and the same builders. Destructuring patterns must include `..`.

### Fixed

- `ReadOptions::skip_method_bodies` now takes precedence over `lazy_method_bodies`,
  avoiding body validation and deferred body storage when both flags are enabled.
  Other lazy options continue to work independently.

## [0.3.1] - 2026-11-01

### Changed

- Conversion tracing spans now use trace level and omit arguments, avoiding large
  debug dumps of metadata contexts when tracing is enabled.
- Updated dependencies, including Bitfield 0.20, num-derive 0.5, Criterion 0.7,
  and `dotnetdll-macros` 0.2.1 with Syn 3 support and improved derive diagnostics.
  Rust 1.85.1 support is preserved. Object remains on 0.38 because its error type
  is exposed in `DLLError::PERead`; Criterion 0.8 requires Rust 1.86.
- Parser regression fixtures no longer depend on prebuilt example artifacts;
  the toolchain and CI test command are pinned for reproducible checks.

### Fixed

- Metadata table bitmasks now compile on ARM32 by using explicit `u64` shifts
  instead of target-dependent bit views.

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

[Unreleased]: https://github.com/nickbclifford/dotnetdll/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/nickbclifford/dotnetdll/compare/v0.3.1...v0.4.0
[0.3.1]: https://github.com/nickbclifford/dotnetdll/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/nickbclifford/dotnetdll/compare/v0.2.0...v0.3.0
