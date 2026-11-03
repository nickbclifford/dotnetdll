# dotnetdll

![Crates.io Version](https://img.shields.io/crates/v/dotnetdll)

A Rust library for reading and writing .NET assembly metadata (DLL/EXE files).

Implements the [ECMA-335](https://www.ecma-international.org/publications-and-standards/standards/ecma-335/) (CLI) standard for .NET metadata manipulation.

> **Status**: Pre-1.0. Core functionality is complete and tested, but the API may evolve before the 1.0 release.

## Features

- **Parse** .NET PE files into structured metadata
- **Generate** .NET assemblies from scratch programmatically  
- **Inspect** types, methods, fields, IL bytecode, custom attributes, and resources
- **Type-safe** navigation using typed indices instead of raw integers
- **Ergonomic** macros for constructing types, signatures, and IL code
- **Lazy reading** options to defer method bodies, signatures, and distribution of common custom attributes (see [`ReadOptions`](https://docs.rs/dotnetdll/latest/dotnetdll/resolution/read/struct.Options.html))
- **Miri support** with opt-in ownership of metadata heap values to reduce Tree Borrows tracking costs

## Quick Start

Add this to your `Cargo.toml`:
```toml
[dependencies]
dotnetdll = "0.4"
```

### Reading a DLL
```rust,no_run
use dotnetdll::prelude::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let bytes = std::fs::read("MyLibrary.dll")?;
    let res = Resolution::parse(&bytes, ReadOptions::default())?;

    for (type_idx, typedef) in res.enumerate_type_definitions() {
        println!("Type: {}", typedef.name);
        
        for (method_idx, method) in res.enumerate_methods(type_idx) {
            println!("  Method: {}", method.name);
        }
    }

    Ok(())
}
```
### Writing a DLL
```rust,no_run
use dotnetdll::prelude::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut res = Resolution::new(Module::new("HelloWorld.dll"));
    res.assembly = Some(Assembly::new("HelloWorld"));

    // Reference external assemblies and types
    let mscorlib = res.push_assembly_reference(
        ExternalAssemblyReference::new("mscorlib")
    );
    let console = res.push_type_reference(
        type_ref! { System.Console in #mscorlib }
    );
    
    // Create a type and method with IL
    let program = res.push_type_definition(
        TypeDefinition::new(None, "Program")
    );
    
    let console_type = BaseType::class(console).into();
    let write_line = res.push_method_reference(
        method_ref! { static void #console_type::WriteLine(string) }
    );
    
    let main = res.push_method(
        program,
        Method::new(
            Accessibility::Public,
            msig! { static void () },
            "Main",
            Some(body::Method::new(asm! {
                load_string "Hello from dotnetdll!";
                call write_line;
                Return;
            })),
        ),
    );
    
    res.set_entry_point(main);

    let bytes = res.write(WriteOptions {
        is_32_bit: false,
        is_executable: true,
    })?;
    
    std::fs::write("HelloWorld.exe", bytes)?;
    Ok(())
}
```

## Reading efficiently

Construct `ReadOptions` with `new()` or `default()` and the `with_*` builders:

```rust
use dotnetdll::prelude::*;

const OPTIONS: ReadOptions = ReadOptions::new()
    .with_lazy_method_bodies(true)
    .with_lazy_attributes(true)
    .with_own_heap_values(cfg!(miri));
```

This configuration decodes method bodies and collects common custom attributes
on demand. Signatures remain eager. Use the accessors below when enabling a lazy
option: the corresponding public fields can contain placeholders or empty values.
All options default to `false`.

| Option | How to read the result |
|---|---|
| `lazy_method_bodies` | `Resolution::method_body`; `Method::body` remains `None` |
| `lazy_method_signatures` | `method_signature` and `method_ref_signature`; public signatures contain placeholders |
| `lazy_property_signatures` | `property_signature`; public property signatures contain placeholders |
| `lazy_attributes` | `type_attributes`, `method_attributes`, `field_attributes`, and `assembly_attributes`; those public attribute lists remain empty |
| `skip_method_bodies` | No bodies are retained or decoded; this overrides `lazy_method_bodies` |
| `own_heap_values` | Retained metadata heap strings and blobs use their existing `Cow::Owned` variants |

Lazy attributes defer distribution to the four listed kinds of owner; other
attribute owners remain eager. Attribute argument decoding is already deferred
until `Attribute::instantiation_data`, independently of `lazy_attributes`.

### Parsing under Miri Tree Borrows

Thousands of retained subslices of one input allocation can make later reads
expensive under Tree Borrows. `own_heap_values` copies retained names, keys,
hashes, security declarations and attribute blobs into separate owned allocations.
Lazy attribute accessors honor the same policy. Deferred method bodies also use
ranges into one shared input slice, reducing persistent input borrows in every
lazy-body parse.

Use `.with_own_heap_values(cfg!(miri))` to enable heap ownership only under Miri.
Explicitly enabling it in native builds adds allocations and copying; the native
default continues to borrow heap values.

**Keep the input alive for the resolution's lifetime.** Heap ownership does not
produce a `Resolution<'static>`: lazy readers and method bodies, field initializers,
and embedded resources can still borrow the input. Decoded attribute arguments
can borrow their attribute blob.

The measured support-DLL consumer tests improved by approximately 6–8 times with
ownership enabled under the pinned Miri Tree Borrows toolchain. Native default
benchmarks showed no material regression. Full CoreLib Miri parsing was not timed;
see the [measurement report](https://github.com/nickbclifford/dotnetdll/blob/v0.4.0/research/owned-heaps/REPORT.md)
for fixtures, flags, native costs, and memory measurements.

### Upgrading from 0.3

`ReadOptions` is now non-exhaustive. Downstream struct literals, including those
using `..Default::default()`, must become builders or assignments after `default()`.
Use `ReadOptions::new()` and the same builders for const configurations. Resolved
field types and lifetimes are unchanged, and the MSRV remains Rust 1.85.1.

See the [0.4 migration guide](https://github.com/nickbclifford/dotnetdll/blob/v0.4.0/docs/migration-0.4.md)
for before/after examples and the skip/lazy precedence change.

## Documentation

- **[API Documentation](https://docs.rs/dotnetdll)** - API reference
- **[Changelog](https://github.com/nickbclifford/dotnetdll/blob/main/CHANGELOG.md)** - Releases and compatibility changes
- **[Examples](https://github.com/nickbclifford/dotnetdll/tree/main/examples)** - Working examples including a DLL dumper and mini-assembler

## Architecture

The library is organized into layers:

- **`resolution`** - High-level API with `Resolution::parse()` and `Resolution::write()`
- **`resolved`** - Semantic types like `TypeDefinition`, `Method`, `Instruction`
- **`binary`** - Low-level ECMA-335 binary structures
- **`dll`** - PE file parsing

Most users only need `resolution` and `resolved`.

## Examples

The repository includes example projects you can learn from:
```bash
# Inspect a DLL
cargo run -p dump-dll -- path/to/Some.dll

# Mini assembler demo
cargo run -p smolasm -- --help
```
## Compatibility

- Rust 1.85.1+ (Rust 2024 edition)
- Supports PE32 and PE64 formats
- Focuses on metadata manipulation, not runtime execution
- Tested against .NET 5+ assemblies

## Contributing

The ownership and deferred-body tests run without a .NET installation:

```bash
cargo test --locked --test owned_heap_values --test deferred_method_bodies
```

The full suite also needs the .NET runtime build described in the
[release and validation guide](https://github.com/nickbclifford/dotnetdll/blob/main/RELEASING.md).

Contributions welcome! Areas where help is especially appreciated:

- Documentation improvements
- Additional examples
- Bug reports and fixes

## License

GPL-3.0-or-later. See [LICENSE](LICENSE).
