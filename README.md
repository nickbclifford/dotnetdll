# dotnetdll

A Rust library for reading and writing .NET assembly metadata (DLL/EXE files).

Implements the [ECMA-335](https://www.ecma-international.org/publications-and-standards/standards/ecma-335/) (CLI) standard for .NET metadata manipulation.

> **Status**: Pre-1.0. Core functionality is complete and tested, but the API may evolve before the 1.0 release.

## Features

- **Parse** .NET PE files into structured metadata
- **Generate** .NET assemblies from scratch programmatically  
- **Inspect** types, methods, fields, IL bytecode, custom attributes, and resources
- **Type-safe** navigation using typed indices instead of raw integers
- **Ergonomic** macros for constructing types, signatures, and IL code

## Quick Start

Add this to your `Cargo.toml`:
```toml
[dependencies]
dotnetdll = "0.1"  # Check crates.io for latest version
```

### Reading a DLL
```rust
use dotnetdll::prelude::*;

fn main() -> Result<(), DLLError> {
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
```rust
use dotnetdll::prelude::*;

fn main() -> Result<(), DLLError> {
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

## Documentation

- **[API Documentation](https://docs.rs/dotnetdll)** - Comprehensive API reference
- **[Examples](examples/)** - Working examples including a DLL dumper and mini-assembler

## Architecture

The library is organized into layers:

- **`resolution`** - High-level API with `Resolution::parse()` and `Resolution::write()`
- **`resolved`** - Semantic types like `TypeDefinition`, `Method`, `Instruction`
- **`binary`** - Low-level ECMA-335 binary structures
- **`dll`** - PE file parsing

Most users only need `resolution` and `resolved`.

## Examples

The repository includes example projects you can learn from:
```
bash
# Inspect a DLL
cargo run -p dump-dll -- path/to/Some.dll

# Mini assembler demo
cargo run -p smolasm -- --help
```
## Compatibility

- Supports PE32 and PE64 formats
- Focuses on metadata manipulation, not runtime execution
- Tested against .NET 5+ assemblies

## Contributing

Contributions welcome! Areas where help is especially appreciated:

- Documentation improvements
- Additional examples
- Bug reports and fixes

## License

GPL-3.0-or-later. See [LICENSE](LICENSE).