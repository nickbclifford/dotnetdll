# Owned heaps and Miri Tree Borrows

Measured 2026-11-02. Local implementation branch: `miri-owned-heaps`.
The crate remains `0.3.1` unreleased; nothing was published or pushed.

## Recommendation and implementation

Use A + D: opt-in ownership of retained metadata heap values, plus internal
ranges for deferred method bodies. Retained strings, public keys/hashes,
attribute blobs and security declarations use their existing `Cow::Owned`
variants. Temporary signature/constant/marshal decoding still reads borrowed
blobs. Public binary readers and all public resolved field types/lifetimes stay
unchanged. Lazy attribute accessors honor the ownership policy. Method bodies
use one input slice and validated ranges instead of one persistent slice per
method. IL is not copied. No library unsafe code was added.

Enable ownership only under Miri for native consumers:

```rust
let options = ReadOptions::new()
    .with_lazy_method_bodies(true)
    .with_lazy_method_signatures(false)
    .with_lazy_attributes(true)
    .with_own_heap_values(cfg!(miri));
```

The ownership flag is independent of every lazy flag. Names/keys/security values
are copied during parse; lazy attributes are copied only when requested. Method
and property signatures keep the same owned decoded representations and error
caching/retry behavior. Body ranges are used only for lazy bodies. Follow-up review
fixed a pre-existing option conflict: `skip_method_bodies` now overrides lazy bodies,
without validating or retaining their ranges; other lazy options remain independent.
Attribute instantiation consults public constructor
signatures, so tests materialize those signatures when testing lazy signatures.

Native zero-copy heap values remain the default. Input lifetimes remain required:
lazy readers/body source, FieldRVA initializers and embedded resources can still
refer to the input. This is not an input-independent `Resolution<'static>` API.

`ReadOptions` is now non-exhaustive, as authorized. This prevents downstream
struct expressions **including `..Default::default()`**; use the builders or
assign fields after `default()`. `ReadOptions::new()` and builders are const,
so downstream const option values remain possible. This is a breaking change;
recommend **0.4.0**, not a 0.3.x patch. The current package version was not bumped.
[Cargo's compatibility guide](https://doc.rust-lang.org/cargo/reference/semver.html)
classifies adding non-exhaustive to an exhaustive public struct as breaking.

## Inventory and isolated alternatives

[INVENTORY.md](INVENTORY.md) lists every retained field/variant and separates
binary-reader fields and later attribute-decoder outputs from parse retention.
There are no public resolved plain `&str`/`&[u8]` fields requiring a tree-wide
API change. The support fixture has 373 deferred body slices, 1,724 extra string
allocations in string-owning mode, six extra retained blob allocations, and no
FieldRVA rows or embedded resources.

The following direct parse measurements use the 46,592-byte support DLL with
lazy bodies, eager signatures and lazy attributes. Each Miri process ran alone;
these are individual observations, not statistical confidence intervals. Native
columns use the allocation-instrumented harness and are approximate; Criterion
results below exclude that instrumentation. Instruction counts include parse
and teardown, measured over three calls and divided by three.

| Alternative | Miri parse (s) | Native debug / release (ms) | Debug / release instructions (M) | Additional retained requested bytes | API / soundness |
|---|---:|---:|---:|---:|---|
| A: strings only | 35.57 | 2.97 / 0.475 | 38.949 / 5.446 | 18,111 | Cow-compatible; no unsafe |
| A: retained blobs only | 291.32 | 3.02 / 0.438 | 37.152 / 4.770 | 205 | Cow-compatible; no unsafe |
| A: strings + retained blobs | 34.84 | 2.98 / 0.482 | 38.949 / 5.449 | 18,316 | Selected ownership policy |
| B: change public borrowed resolved fields | N/A | N/A | N/A | N/A | No such fields exist; changing binary Reader values would be an unnecessary public break |
| C: borrowed strings/blob heaps in separate caller-owned allocations | 195.44 | 4.66 / 0.421 | 37.144 / 4.766 | 12,956 outside Resolution | Prototype is safe; requires caller storage/lifetime plumbing |
| D + A: ranges + owned heaps | 28.51 | 2.98 / 0.469 | 38.966 / 5.449 | 22,188 | Selected, no new unsafe or public lifetime changes |

C's heap copy/setup occurs before its parse timer. Its two allocations must stay
alive until the resolution is dropped. Putting these local buffers inside the
current parser and returning borrows into them would require a self-referential
owner or an external storage argument; the present lifetimes do not allow
returning references to local copies. Copying a whole heap also leaves all its
names in one borrow tree, which explains why it remains slow (inference,
supported by the measured class separation). Copies per retained value isolate
the long-lived tags much more effectively. No leaking allocations were used.

D alone remains zero-copy and adds 3,872 requested bytes on the support DLL.
Storing `Option<range + offset>` takes more space than the old slice's non-null
niche, plus the shared input slice. Its native allocation count is unchanged.
Deferring names by heap index would require public accessor/layout changes and
move costs to access; it was not implemented or assigned speculative timings.

## Real consumer

The baseline is an archived checkout of dotnetdll main at
`ddab300e9f2353ebbe510f14c1ada2da856392f4`, patched into a scratch dotnet-rs
worktree at `893d7f8ae89f024b91450af5150a8a205540efca`. The final run uses this
branch with ownership explicitly enabled. Separate target directories were used;
no main dotnet-rs files or build cache were modified. Initial published-0.3.0
rechecks measured 298.12 s for p00; A alone measured 39.56 s.

| Test | Local-main baseline | Final A+D | Speedup |
|---|---:|---:|---:|
| `pointer_provenance_tests::p00_smoke` | 271.04 s | 35.11 s | 7.72x |
| `pointer_provenance_tests::batches::batch_2` | 234.29 s | 40.10 s | 5.84x |

Flags in every final consumer Miri run:
`-Zmiri-tree-borrows -Zmiri-disable-isolation -Zmiri-ignore-leaks`,
nightly-2026-05-27, exact filter and one test thread. Rayon and alias checking
were not changed. Miri durations are the harness's test duration, excluding
compilation. Baseline/final parser dependencies use the local 0.3.1 package,
which satisfies the consumer's `dotnetdll = "0.3.0"` requirement for this local
patch. A published 0.4.0 will require a consumer dependency bump to `"0.4"`.
Other consumer ReadOptions literals also need builder/field-assignment migration.
Consumer DLLs built in the two target directories have different MVIDs and whole-file
hashes, but identical `#~`, `#Strings`, `#Blob` and `#US` stream fingerprints and sizes;
both remain 46,592 bytes with the same table populations.
The measured patch enables ownership unconditionally to test the mode natively;
use `cfg!(miri)` for adoption. The scratch adoption patch is saved with the measurement logs; no consumer
commit was made and its worktree was removed after testing.

## Native performance and CoreLib impact

Criterion: Rust 1.85.1, release profile, 30 samples, 1-second warmup,
2-second measurement target, `RAYON_NUM_THREADS=1`. Eager CoreLib needs more than
two seconds for 30 samples; an additional three-second eager rerun checks noise.
No code changes to Rayon or its parallelism threshold were made. Some early
runs overlapped compilation and were noisy; use the steady/combined runs and
repeated eager observations, not the largest apparent speedups.

| CoreLib mode | Before (borrowed), ms | Final default, ms | Final owned, ms |
|---|---:|---:|---:|
| Eager | 116.90 (repeat: 115.48) | 116.60 | 129.93 |
| Lazy bodies, eager attributes/signatures | 54.32 | 53.51 | 63.62 |
| Lazy method signatures, eager bodies | 97.48 | 96.09 | 111.39 |
| Lazy bodies + method signatures | 34.74 | 34.66 | 43.80 |
| Production: lazy bodies/signatures/attributes | 33.38 | 31.97 | 40.83 |
| Support-style: lazy bodies/attributes, eager signatures | not in old Criterion harness | 51.03 | 58.35 |

The support-DLL Criterion consumer case measures **365.6 us default / 400.6 us
owned** in the final code. The separate debug allocation-instrumented harness
measures **2.832 ms before / 2.769 ms final default / 2.976 ms final owned**;
release is **0.410 / 0.398 / 0.469 ms**. Native observations fluctuate by a few
percent. The final default instruction deltas are +0.317% debug / +0.088% release (37.155 / 4.769 million instructions);
there is no material evidence of a native throughput regression. Explicitly
owning values costs native time, hence the `cfg!(miri)` adoption recommendation.

CoreLib here is the local debug runtime's `System.Private.CoreLib.dll` (6,389,248
bytes, runtime artifacts version directory 11.0.0), not a claim about every
installed release CoreLib. It has 43,393 methods and 41,270 deferred body slices.
D removes that slice population in all modes, replacing it with one input borrow.
**Full CoreLib Miri parse time was not measured**; the reduction of its alias
population is an inference about Miri scalability, not a measured runtime.

Requested live/peak heap bytes from the native metered allocator:

| CoreLib mode | Before live | Final default live | Final owned live | Final owned peak extra | Extra allocations for ownership |
|---|---:|---:|---:|---:|---:|
| Eager | 203,741,120 | 203,741,120 | 205,859,164 | 228,192,524 | 173,734 |
| Lazy bodies | 96,066,968 | 96,414,128 | 98,532,172 | 108,048,492 | 173,734 |
| Support-style | 96,908,168 | 97,255,328 | 98,953,523 | 108,469,843 | 145,228 |
| Production lazy | 78,260,048 | 78,607,208 | 80,305,403 | 89,821,723 | 145,228 |

D's lazy-state overhead is 347,160 bytes (~339 KiB) on this CoreLib. Owning heaps
adds another 1,698,195 bytes (~1.62 MiB) with lazy attributes or 2,118,044 bytes
(~2.02 MiB) with eager attributes. Metadata stays alongside the original input;
ownership does not release that input. Allocation counts include reallocations.
These are requested Rust allocation bytes, excluding allocator headers, input
storage and warmed Rayon threads. A fresh-process RSS check for production mode
measured 118,064 KiB default / 122,004 KiB owned in the final code; RSS is a coarse
single observation and includes allocator effects. Miri RSS was not measured.

## Validation, reproducibility and upstream follow-up

- `cargo +1.85.1 test --workspace` with `DOTNET_SDK=/usr/bin/dotnet` and
  `RUNTIME_ARTIFACTS=/home/nick/Desktop/runtime/artifacts`: passes, including
  CoreLib eager/lazy body equality and the new CoreLib ownership comparison.
- Self-contained ownership tests compare all 16 lazy-flag combinations, public
  names/signatures/attributes, lazy accessor results, and cloning/dropping the
  original resolution. A separate representative fixture compares all public
  fields, including external references. Private attribute-Cow tests assert
  ownership in eager and lazy modes.
- The Miri small-fixture smoke asserts actual owned variants and exercises lazy
  bodies, attributes and const option construction: passes (2.95 s).
- Follow-up range review confirms `raw_rva` returns nonempty subslices of the original
  input, so address subtraction and the stored end index remain in bounds. Alignment
  handling is unchanged. New self-contained regressions cover PE32/PE32+ tiny/fat
  bodies, padding, cold clones and their shared cache, zero-RVA methods, invalid
  RVAs, malformed/truncated IL, retrying decode errors, and skip/lazy precedence.
  CI now explicitly checks Rust 1.85.1 and runs the ownership smoke and range tests
  under the pinned Tree Borrows configuration.
- Consumer native tests: 51 passed; 94 passed, six ignored by the existing suite. Fixture files were copied
  read-only from the existing consumer fixture build into scratch storage for
  the five host tests that otherwise fail because a fresh worktree lacks fixtures.
- Clippy completes with existing repository warnings; new ownership helpers use
  `must_use` builders and retain explicit debug inlining to keep overhead small.
  The minimum compiler remains Rust 1.85.1; `ptr::addr` is available there.

The standalone probe workspace in this directory measures requested allocation
bytes, tables and fresh-read scaling. `make_probes.py` creates disposable A-only
class probes or the final A+D parser (`--ranges`); all experimental environment
reads and stage prints are confined to those copies. Pass the class as a command
argument under Miri, since arbitrary host environment variables are not forwarded
by default. No class-selection or eprintln instrumentation ships in the library.

Examples:

```bash
python3 research/owned-heaps/make_probes.py /tmp/heap-classes
MIRIFLAGS="-Zmiri-tree-borrows -Zmiri-disable-isolation -Zmiri-ignore-leaks" \
  cargo +nightly-2026-05-27 miri run --manifest-path /tmp/heap-classes/Cargo.toml \
  --example heap_probe -- /path/to/support.dll owned strings
DOTNETDLL_BENCH_DLL=/path/to/support.dll RAYON_NUM_THREADS=1 \
  cargo bench --bench parse -- consumer
cargo bench --features stage-timing --bench stage_timing -- \
  --input /path/to/support.dll --mode consumer --own-heap-values
```

Raw logs and the scratch consumer patch are under `/tmp/dotnetdll-measurements`;
compact observations are retained in `results.json`. Support SHA-256:
`720120f3049d58e6a62a4e3e64e95fb8fb13bdc94fbf2ec5cb5555e788596829`.
CoreLib SHA-256:
`22abea031395740f763f1db8e383a760f5a7071d6cfb86c618634b6c6eba94c9`.
Pinned Miri compiler: `rustc 1.98.0-nightly (d1fc603d1 2026-05-26)`, LLVM 22.1.6.

An upstream performance issue is worth pursuing. The all-safe standalone
reproducer reads 16 bytes 100 times while tiny shared slices remain live.
N=0: 0.1014 s; N=600: 5.4884 s; N=1500: 60.3760 s (read-loop time only). The last process took 184.55 s including construction/startup. This supports a borrow-tree scaling problem independently of
.NET parsing; it does not establish an exact complexity bound. Miri's
[tree implementation](https://github.com/rust-lang/miri/blob/master/src/borrow_tracker/tree_borrows/tree.rs)
describes traversal and pruning optimizations; current nightly may differ from
the pinned version. [MIRI_ISSUE_DRAFT.md](MIRI_ISSUE_DRAFT.md) contains the draft
and minimal reproducer instructions. It was **not filed**.

## Pre-merge review

The range review found no new unsafe code or lifetime changes. `raw_rva` uses
object's checked section lookup: an RVA must lie strictly inside the readable
section, and the result is a nonempty subslice of the original input. Thus
subtracting the base addresses gives an in-bounds start index, and adding that
subslice's length cannot exceed the input length. Decode uses the same immutable
input, including across `Resolution` clones. Header alignment is unchanged;
the range validates storage, not the deferred header or IL encoding.

A regression reproduced the pre-existing skip/lazy conflict before the fix.
Normalizing the effective lazy-body flag once at parser entry now makes skip
take precedence, including for invalid body RVAs, while independent lazy signature,
property and attribute state remains available. The six new regression tests
pass natively and under the pinned Tree Borrows flags (**20.23 s**); the ownership
smoke also passes again (**3.16 s**).

Final Rust 1.85.1 workspace tests, the all-target/all-feature check, docs and
package verification pass. Package verification used `--locked`, `--offline` and
`--allow-dirty` before committing; no registry upload occurred. Clippy completes
with existing warnings and none in the new range tests. Workflow YAML parses,
and its MSRV and Miri commands were exercised locally; hosted CI awaits a push
or pull request. The resource-read test was additionally run against a freshly
built scratch project because the checkout's existing .NET `obj`/`bin` directories
belong to another UID, preventing an in-place rebuild.

A fresh native run compared against hours-old Criterion samples initially showed
a higher CoreLib default time (33.95 ms). A subsequent direct comparison with the
preserved pre-review A+D benchmark binary controls for that temporal variation.
Both binaries used Rust 1.85.1, the same DLLs, one Rayon thread, 30 samples,
one-second warmup and two-second measurement targets. The second CoreLib pair
ran in reverse order:

| Case | Pre-review A+D | Reviewed implementation | Repeat before / after |
|---|---:|---:|---:|
| Support consumer, default | 354.20 us | 346.08 us | — |
| Support consumer, owned | 392.42 us | 393.73 us | — |
| CoreLib production lazy, default | 32.159 ms | 32.153 ms | 31.939 / 32.196 ms |
| CoreLib production lazy, owned | 40.441 ms | 40.406 ms | 40.531 / 40.106 ms |

These contemporaneous observations show no material native regression from the
skip/lazy fix. Raw follow-up logs use the `review-` prefix in the same measurement
directory; the original before/after measurements above remain unchanged.

Consumer verification was repeated in a fresh scratch worktree of dotnet-rs at
`6915ef7011a694c99f02419033cc3870b630989b`, using the same unconditional-owned
adoption patch and separate target directory. Native tests again passed (51
assembly tests; 94 VM tests, six existing ignores). Sequential Tree Borrows runs
also passed: **p00 39.29 s**, **batch_2 45.17 s**, excluding compilation. These
are follow-up observations on a newer consumer commit, not replacements for the
original controlled before/after comparison. The scratch patch was retained as
`review-consumer-owned.patch`; the worktree was removed without a consumer commit.
