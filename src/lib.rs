//! # dotnetdll
//!
//! A Rust library for reading and writing .NET assembly metadata, implementing the ECMA-335 (CLI) standard.
//!
//! ## Overview
//!
//! `dotnetdll` provides a complete toolkit for working with .NET metadata at both high and low levels.
//! You can parse existing DLLs, inspect their contents, modify metadata, and generate new assemblies from scratch.
//!
//! The library is organized into several layers, each serving different use cases:
//!
//! - **[`resolution`]**: High-level API for parsing and writing DLLs
//! - **[`resolved`]**: Semantic metadata types (types, methods, IL instructions)
//! - **[`binary`]**: Low-level ECMA-335 binary structures
//! - **[`dll`]**: PE file parsing
//!
//! Most users will work primarily with [`resolution`] and [`resolved`].
//!
//! ## The `Resolution` Struct
//!
//! [`resolution::Resolution`] is the central data structure. It represents all metadata from a DLL:
//!
//! - **Types**: [`type_definitions`](resolution::Resolution::type_definitions) and [`type_references`](resolution::Resolution::type_references)
//! - **Methods/Fields**: [`method_references`](resolution::Resolution::method_references) and [`field_references`](resolution::Resolution::field_references)
//! - **Assemblies**: [`assembly`](resolution::Resolution::assembly) and [`assembly_references`](resolution::Resolution::assembly_references)
//! - **Resources**: [`manifest_resources`](resolution::Resolution::manifest_resources)
//!
//! ### Parsing a DLL
//!
//! ```rust,no_run
//! use dotnetdll::prelude::*;
//!
//! let bytes = std::fs::read("MyLibrary.dll").unwrap();
//! let res = Resolution::parse(&bytes, ReadOptions::default()).unwrap();
//!
//! // Access the assembly name
//! if let Some(assembly) = &res.assembly {
//!     println!("Assembly: {}", assembly.name);
//! }
//!
//! // Iterate over all type definitions
//! for (type_idx, typedef) in res.enumerate_type_definitions() {
//!     println!("Type: {}", typedef.name);
//! }
//! ```
//!
//! ### Creating a new assembly
//!
//! ```rust,no_run
//! use dotnetdll::prelude::*;
//!
//! let mut res = Resolution::new(Module::new("Example.dll"));
//! res.assembly = Some(Assembly::new("Example"));
//!
//! // Add types, methods, etc.
//! let my_type = res.push_type_definition(
//!     TypeDefinition::new(Some("MyNamespace".into()), "MyClass")
//! );
//!
//! let bytes = res.write(WriteOptions::default()).unwrap();
//! std::fs::write("Example.dll", bytes).unwrap();
//! ```
//!
//! ## Typed Indices
//!
//! Instead of using raw `usize` indices, `dotnetdll` uses typed index wrappers like
//! [`resolution::TypeIndex`], [`resolution::MethodIndex`], and [`resolution::FieldIndex`]
//! that automatically index into the correct metadata table from a resolution.
//!
//! ```rust,no_run
//! use dotnetdll::prelude::*;
//! # let bytes = &[];
//! # let res = Resolution::parse(bytes, ReadOptions::default()).unwrap();
//!
//! if let Some(type_idx) = res.type_definition_index(0) {
//!     let typedef = &res[type_idx];
//!     println!("{}", typedef.name);
//! }
//!
//! // Enumerate with typed indices
//! for (type_idx, typedef) in res.enumerate_type_definitions() {
//!     // type_idx is a TypeIndex, not usize
//!     for (method_idx, method) in res.enumerate_methods(type_idx) {
//!         // method_idx is a MethodIndex
//!         println!("  {}", method.name);
//!     }
//! }
//! ```
//!
//! ## Type System
//! To prevent certain simple metadata errors at compile time, `dotnetdll` uses a composed type hierarchy:
//! - [`resolved::types::BaseType`] - Core types (primitives, pointers, arrays)
//! - [`resolved::types::MemberType`] - For fields, properties (allows type generics: `T0`, `T1`, ...)
//! - [`resolved::types::MethodType`] - For method signatures (allows both type and method generics: `T0`, `M0`, ...)
//!
//! This design prevents method-level generic variables (`M0`, `M1`) from appearing in field types,
//! where they would be invalid.
//!
//! ```rust
//! use dotnetdll::prelude::*;
//! # let mut res = Resolution::new(Module::new("test"));
//! # let type_idx = res.type_definition_index(0).unwrap();
//!
//! // Fields use MemberType (only type-level generics allowed)
//! let field = Field::instance(
//!     Accessibility::Private,
//!     "myField",
//!     ctype! { string[] }  // MemberType
//! );
//!
//! // Method parameters use MethodType (type and method generics allowed)
//! let method = Method::new(
//!     Accessibility::Public,
//!     msig! { string (int, bool) },  // MethodType in signature
//!     "MyMethod",
//!     None
//! );
//! ```
//!
//! ## Macros
//!
//! `dotnetdll` provides a small set of convenience macros that are documented where you will
//! typically discover and use them:
//!
//! - Type construction: [`resolved::types::ctype!`]
//! - Type references: [`resolved::types::type_ref!`]
//! - Method signatures: [`resolved::signature::msig!`]
//! - IL instruction lists + labels: [`asm!`] (see [`resolved::il`])
//! - Accessibility keywords: [`access!`] (see [`resolved`])
//! - External member references: [`resolved::members::method_ref!`], [`resolved::members::field_ref!`]
//!
//! The constructor-style macros support *substitution* of existing Rust values via `#var` (move) and
//! `@var` (clone); see the `ctype!`/`msig!` docs for details.
//!
//! ## Working with IL
//!
//! IL instructions are represented with the [`resolved::il::Instruction`] enum. Branch targets use
//! instruction indices (not byte offsets) - the library handles offset calculation automatically.
//!
//! See [`resolved::il`] for the complete instruction set and [`resolved::body::Method`] for method body construction.
//!
//! ## Custom Attributes
//!
//! Custom attributes can be added to most metadata elements. To decode their instantiation data,
//! you need a [`resolved::types::Resolver`] that can locate referenced types.
//!
//! See [`resolved::attribute`] for details.
//!
//! ## Error Handling
//!
//! Operations that can fail return [`Result<T, DLLError>`](dll::DLLError). Common errors include:
//!
//! - Invalid PE format
//! - Malformed metadata tables
//! - Invalid signatures or IL bytecode
//!
//! ## Examples
//!
//! The repository includes two example projects:
//!
//! - **`dump-dll`** - Parses and prints DLL contents (good for learning the API)
//! - **`smolasm`** - Mini-assembler demonstrating metadata construction
//!
//! Run them with:
//! ```bash
//! cargo run -p dump-dll -- path/to/Some.dll
//! cargo run -p smolasm -- --help
//! ```
//!
//! ## ECMA-335 Standard
//!
//! This library implements the Common Language Infrastructure physical format as specified in the
//! [ECMA-335](https://www.ecma-international.org/publications-and-standards/standards/ecma-335/) standard.
//! Familiarity with the standard is very helpful, but ultimately not required.

#![warn(clippy::pedantic)]
#![allow(
    clippy::cast_lossless,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss,
    clippy::doc_lazy_continuation,
    clippy::doc_markdown,
    clippy::enum_glob_use,
    clippy::items_after_statements,
    clippy::match_wildcard_for_single_variants,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::must_use_candidate,
    clippy::struct_excessive_bools,
    clippy::uninlined_format_args,
    clippy::wildcard_imports
)]

#[macro_use]
mod utils {
    macro_rules! check_bitmask {
        ($mask:expr, $val:literal) => {
            $mask & $val == $val
        };
    }

    macro_rules! build_bitmask {
        ($target:expr, $($field:ident => $val:literal),+) => {{
            let mut mask = 0;
            $(
                if $target.$field {
                    mask |= $val;
                }
            )+
            mask
        }}
    }

    macro_rules! try_into_ctx {
        ($t:ty, |$s:ident, $buf:ident| $e:expr) => {
            try_into_ctx!(() => $t, |$s, $buf, _ctx| $e);
        };
        ($ctx:ty => $t:ty, |$s:ident, $buf:ident, $ctx_i:ident| $e:expr) => {
            impl TryIntoCtx<$ctx> for $t {
                type Error = scroll::Error;

                fn try_into_ctx(
                    $s,
                    $buf: &mut [u8],
                    $ctx_i: $ctx,
                ) -> std::result::Result<usize, Self::Error> {
                    $e
                }
            }

            impl TryIntoCtx<$ctx, scroll_buffer::DynamicBuffer> for $t {
                type Error = scroll::Error;

                fn try_into_ctx(
                    $s,
                    $buf: &mut scroll_buffer::DynamicBuffer,
                    $ctx_i: $ctx,
                ) -> std::result::Result<usize, Self::Error> {
                    $e
                }
            }
        };
    }

    use std::hash::*;

    pub fn hash(val: impl Hash) -> u64 {
        let mut hasher = DefaultHasher::new();
        val.hash(&mut hasher);
        hasher.finish()
    }

    pub fn round_up_to_4(mut val: usize) -> (usize, usize) {
        let rem = val % 4;
        if rem != 0 {
            val += 4 - rem;
        }
        (val, rem)
    }
}

pub mod binary;
mod convert;
pub mod dll;
pub mod resolution;
pub mod resolved;

/// Commonly used types and traits for working with dotnetdll.
///
/// This module re-exports the most frequently used items to simplify imports.
/// Most code using this library should start with:
///
/// ```rust
/// use dotnetdll::prelude::*;
/// ```
pub mod prelude {
    pub use crate::{
        access, asm,
        dll::{DLLError, DLL},
        resolution::{read::Options as ReadOptions, utils::*, write::Options as WriteOptions, *},
        resolved::{
            assembly::*,
            attribute::*,
            body, generic,
            il::*,
            members::{Accessibility as MemberAccessibility, *},
            module::*,
            resource,
            signature::*,
            types::{Accessibility as TypeAccessibility, *},
            Accessibility, ResolvedDebug,
        },
    };
}

#[cfg(test)]
mod tests {
    #[test]
    pub fn constructor_macros() {
        use super::resolved::{signature::*, types::*};

        let m: MethodType = ctype! { string[] };
        println!("{:?}", m);
        let m: MethodType = ctype! { bool };
        println!("{:?}", m);
        let m: MethodType = ctype! { char[]* };
        println!("{:?}", m);
        let m: MethodType = ctype! { void*[] };
        println!("{:?}", m);

        let m: ManagedMethod<_> = msig! { string (int, ref #m) };
        println!("{:?}", m);
        let m: ManagedMethod<MethodType> = msig! { static void (string[]) };
        println!("{:?}", m);
    }
}
