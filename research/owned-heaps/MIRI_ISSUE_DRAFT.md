# Draft only — not filed

Title: Tree Borrows: repeated reads scale sharply with unrelated live shared slices

On nightly-2026-05-27, a safe program that retains many small shared slices into
one allocation makes subsequent fresh read-only borrows of that allocation much
slower under Tree Borrows. No mutation or unsafe code is involved. A real example
is .NET metadata parsing: a 46,592-byte DLL supplies many retained names/blobs,
while later stages keep reading its metadata and method bytes.

Reproducer: `tree_borrows.rs` in this directory (standalone Cargo bin).

```bash
MIRIFLAGS="-Zmiri-tree-borrows -Zmiri-disable-isolation -Zmiri-ignore-leaks" \
  cargo +nightly-2026-05-27 miri run \
  --manifest-path research/owned-heaps/Cargo.toml --bin tree_borrows -- 600
```

Run each value of N (0, 300, 600, 1500) in a fresh process, with no concurrent
Miri processes. The printed duration covers only 100 fresh 16-byte reads, after
constructing the live slice collection. Keep `black_box(borrows)` after the reads
so the collection remains live. Compare the same source under Stacked Borrows
only as a diagnostic control; the proposed library fix preserves Tree Borrows.

Hypothesis: allocation-wide borrow-tree traversal makes fresh reads expensive
as the live tree grows; the growth is substantially worse than the byte count
read. This is a performance report, not a claim that the aliasing model is wrong.
The default crate parser keeps zero-copy behavior; an opt-in policy copies
retained Cow values and reduces the real consumer's runtime substantially.

Measurements and exact source/toolchain fingerprints are in REPORT.md. These
results describe the pinned nightly, not an assertion that current Miri has the
same performance. Before filing, rerun this small reproducer on current nightly
and check for duplicate issues. No issue has been filed by this task.

## Observed on the pinned nightly

| Live slices | 100 reads | Whole command (including creation/startup) |
|---:|---:|---:|
| 0 | 0.1014 s | 3.76 s |
| 600 | 5.4884 s | 11.58 s |
| 1500 | 60.3760 s | 184.55 s |

Creating the live slice population is itself expensive, so allow several minutes
for the largest run. The read loop's separate timer is the quantity compared here.
The source is all safe Rust and uses only `std`; it can be copied into a fresh
`cargo new` binary project to avoid building the unrelated probe dependency.
