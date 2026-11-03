# Releasing dotnetdll

The root crate and `dotnetdll-macros` have independent versions. Publish the macros
crate first only when its version changes; dotnetdll 0.4.0 uses the already
published macros 0.2.1. Do not publish the example or research packages.

## Prepare the release commit

1. Update the root package version, the root and research lockfiles, and README
   dependency examples. Keep `rust-version` at the tested MSRV.
2. Move changes from `[Unreleased]` into a dated changelog entry, leaving an empty
   `[Unreleased]` section. Update comparison links and distinguish changes that
   shipped in earlier versions.
3. Document breaking changes in a migration guide. Prepare the GitHub release
   body in `docs/releases/<version>.md`.

## Verify

Run the self-contained checks on Rust 1.85.1:

```bash
cargo +1.85.1 fmt --all -- --check
cargo +1.85.1 check --workspace --all-targets --all-features --locked
cargo +1.85.1 test --locked --test owned_heap_values --test deferred_method_bodies
cargo +1.85.1 test --doc --locked
cargo +1.85.1 doc --no-deps --all-features --locked
```

The full suite requires a .NET SDK and a debug build of `dotnet/runtime` with
`clr+libs -rc debug`. The runtime artifacts must include `ilasm`, `ildasm`,
CoreCLR, and a testhost with `System.Private.CoreLib.dll`. Point the environment
at those tools and run:

```bash
DOTNET_SDK=/path/to/dotnet RUNTIME_ARTIFACTS=/path/to/runtime/artifacts \
  cargo +1.85.1 test --workspace --locked
```

The repository's prebuilt test container supplies that environment:

```bash
docker compose run tests /cargo/bin/cargo test --locked
```

Run the pinned Miri tests sequentially:

```bash
rustup toolchain install nightly-2026-05-27 --profile minimal --component miri --component rust-src
cargo +nightly-2026-05-27 miri setup
export MIRIFLAGS="-Zmiri-tree-borrows -Zmiri-disable-isolation -Zmiri-ignore-leaks"
cargo +nightly-2026-05-27 miri test --locked --test owned_heap_values miri_owned_heap_smoke -- --exact --test-threads=1
cargo +nightly-2026-05-27 miri test --locked --test deferred_method_bodies -- --test-threads=1
```

Finally, from a clean committed tree, check the published package rather than
only the workspace path dependencies:

```bash
cargo +1.85.1 package --list --locked
cargo +1.85.1 publish --dry-run --locked -p dotnetdll
```

Inspect the archive under `target/package`. The migration guide and release notes
should be included. The nested research package is kept in Git and linked from
the docs rather than bundled in the crate. A dry run does not upload anything.

## Merge and publish

These commands write to GitHub or crates.io; run them when the release is
authorized. Merge the tested branch after all CI jobs pass, then use a clean
checkout of the resulting main commit. Do not amend the release after publishing.

For 0.4.0:

```bash
git switch main
git pull --ff-only origin main
cargo +1.85.1 publish --locked -p dotnetdll
git tag -a v0.4.0 -m "Release dotnetdll 0.4.0"
git push origin v0.4.0
gh release create v0.4.0 --verify-tag --title "dotnetdll 0.4.0" --notes-file docs/releases/0.4.0.md
```

Verify the crates.io version and docs.rs build after publishing. Cargo uploads
are permanent; if an upload fails, check the registry before retrying. Keep the
Git tag on the exact commit that produced the published crate.
