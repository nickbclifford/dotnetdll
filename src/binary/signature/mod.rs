//! ECMA-335 binary signature blob structures.
//!
//! This module models byte-level encodings stored in `#Blob`, including compressed integers,
//! element-type tags, and method/field/property/custom-attribute signature forms.
//!
//! ECMA-335 references: `ECMA-335, II.23.2`, `ECMA-335, II.23.3`, and `ECMA-335, II.23.4`.
//!
//! Submodules:
//! - [`compressed`] — compressed integer encoding used in signatures
//! - [`encoded`] — element-type constants and shared encoded signature components
//! - [`kinds`] — method, field, property, local-variable, and marshal signature kinds
//! - [`attribute`] — custom-attribute fixed and named argument encodings

pub mod attribute;
pub mod compressed;
pub mod encoded;
pub mod kinds;
