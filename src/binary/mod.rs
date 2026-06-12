//! Low-level ECMA-335 binary encoding layer.
//!
//! This module contains the physical representation used in .NET PE/CLI files: metadata tables and
//! indices, metadata heaps/streams, signature blobs, method body bytecode, and CLI headers.
//!
//! It maps directly to ECMA-335 Partition II encoding sections:
//! - metadata tables (`ECMA-335, II.22`)
//! - signatures and blobs (`ECMA-335, II.23`)
//! - metadata streams/heaps layout (`ECMA-335, II.24`)
//! - PE/CLI file and method body format (`ECMA-335, II.25`)
//!
//! Most users work through [`crate::resolution`] and [`crate::resolved`], which build semantic
//! APIs on top of these binary structures.
//!
//! Submodules:
//! - [`cli`] — CLI header and metadata root structures
//! - [`metadata`] — table rows, tokens, and index encodings
//! - [`signature`] — signature and custom-attribute blob structures
//! - [`heap`] — `#Strings`, `#Blob`, `#GUID`, and `#US` heap readers/writers
//! - [`method`] and [`il`] — method body structure and IL bytecode encoding
//! - [`stream`] — metadata stream header entries

#[macro_use]
mod utils {
    macro_rules! throw {
        ($($arg:tt)*) => {
            return Err(scroll::Error::Custom(format!($($arg)*)))
        }
    }
}

pub mod cli;
pub mod heap;
pub mod il;
pub mod metadata;
pub mod method;
pub mod signature;
pub mod stream;
