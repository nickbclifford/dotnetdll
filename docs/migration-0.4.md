# Migrating to dotnetdll 0.4

Update the dependency requirement:

```toml
[dependencies]
dotnetdll = "0.4"
```

The minimum Rust version remains **1.85.1**. Public resolved field types and
lifetimes are unchanged. The `dotnetdll-macros` dependency remains at 0.2.1.

## Constructing read options

`ReadOptions` is now `#[non_exhaustive]`, allowing options to be added without
another struct-construction break. Existing downstream literals no longer compile,
including literals with `..Default::default()`.

Before, in 0.3:

```rust,ignore
let options = ReadOptions {
    lazy_method_bodies: true,
    lazy_method_signatures: false,
    lazy_attributes: true,
    ..Default::default()
};
```

After, in 0.4:

```rust
use dotnetdll::prelude::ReadOptions;

let options = ReadOptions::new()
    .with_lazy_method_bodies(true)
    .with_lazy_method_signatures(false)
    .with_lazy_attributes(true);
```

`new()` and `default()` have the same defaults: all flags are false. Every
`with_*` method accepts a boolean, returns the updated options, and works in const
contexts:

```rust
use dotnetdll::prelude::ReadOptions;

const OPTIONS: ReadOptions = ReadOptions::new()
    .with_lazy_method_bodies(true)
    .with_lazy_attributes(true)
    .with_own_heap_values(cfg!(miri));
```

Fields remain public, so assignment after construction also works:

```rust
use dotnetdll::prelude::ReadOptions;

let mut options = ReadOptions::default();
options.lazy_method_bodies = true;
```

Destructuring patterns must include `..`:

```rust
use dotnetdll::prelude::ReadOptions;

let options = ReadOptions::default();
let ReadOptions { lazy_method_bodies, .. } = options;
```

`WriteOptions` construction is unchanged.

## Enabling owned heap values under Miri

Add `.with_own_heap_values(cfg!(miri))` to the migrated options. This selects
ownership when compiled by Miri while retaining native zero-copy heap behavior.
It is independent of all lazy options and defaults to false.

Owned values include retained metadata names, namespaces, keys, hashes, security
declarations and attribute blobs. Lazy attribute accessors copy their retained
blobs when requested. Temporary signature, constant and marshal decoding continues
to read heap data directly. The public resolved fields already use `Cow`, so
reading their contents works as before; code inspecting `Cow::Borrowed` versus
`Cow::Owned` will observe the selected policy.

Keep the original input alive. The flag does not remove the input lifetime from
`Resolution`: lazy readers, IL bodies, field initializers and embedded resources
can still refer to the input. Attribute arguments decoded later can borrow their
attribute blob. Enabling ownership in native builds adds allocations and copying.

The internal range representation for lazy method bodies applies automatically;
it needs no extra option and does not copy IL. Full CoreLib Miri parsing has not
been timed. See the [research report](../research/owned-heaps/REPORT.md) for the
measured support-DLL speedups and native/memory tradeoffs.

## Combining skip and lazy bodies

`skip_method_bodies` now takes precedence over `lazy_method_bodies`. Previously,
enabling both flags still allowed lazy body decoding. With both enabled in 0.4:

- Body RVAs are not validated and no deferred body state is retained.
- `Method::body` is `None`, and `Resolution::method_body` returns an error.
- Lazy method/property signatures and custom attributes still work independently.

If you want on-demand bodies, leave `skip_method_bodies` false. If you want to
exclude bodies entirely, set it true.

The existing lazy accessor rules remain: use `method_body`, `method_signature`,
`method_ref_signature`, `property_signature`, and the four attribute accessors for
the corresponding lazy modes. Their public fields can contain placeholders or
empty values. `lazy_attributes` defers distribution for types, methods, fields
and the assembly; attribute value decoding remains separately deferred until
`Attribute::instantiation_data` is called.
