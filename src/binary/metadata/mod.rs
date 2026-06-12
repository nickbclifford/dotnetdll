//! Logical metadata (`#~`) stream structures and index encodings.
//!
//! This module contains metadata table row types plus the simple/coded index types used to refer
//! to table rows and heap entries.
//!
//! ECMA-335 references: `ECMA-335, II.22`, `ECMA-335, II.23`, and `ECMA-335, II.24`.
//!
//! Submodules:
//! - [`table`] — metadata table kinds and row structures
//! - [`index`] — metadata tokens, simple indices, coded indices, and heap indices
//! - [`header`] — `#~` stream header fields and sizing flags

#[macro_use]
pub mod table;

pub mod header;
pub mod index;
