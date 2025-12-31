use super::attribute::Attribute;
use crate::resolution::{AssemblyRefIndex, FileIndex};
use std::borrow::Cow;

/// Specifies the location of a manifest resource's data.
#[derive(Debug, Clone)]
pub enum Implementation<'a> {
    /// The resource is located in an external file within the assembly.
    File { location: FileIndex, offset: usize },
    /// The resource is located in an external assembly.
    Assembly { location: AssemblyRefIndex, offset: usize },
    /// The resource data is embedded directly within the current file.
    CurrentFile(Cow<'a, [u8]>),
}

/// Specifies the visibility of a manifest resource.
#[derive(Debug, Copy, Clone)]
pub enum Visibility {
    /// The resource is visible outside the assembly.
    Public,
    /// The resource is only visible within the assembly.
    Private,
}

/// A resource included in the assembly's manifest.
///
/// See ECMA-335, II.22.24 (page 232) for more information.
#[allow(clippy::module_name_repetitions)]
#[derive(Debug, Clone)]
pub struct ManifestResource<'a> {
    /// All attributes present on the resource declaration.
    pub attributes: Vec<Attribute<'a>>,
    /// Name of the resource.
    pub name: Cow<'a, str>,
    /// Visibility of the resource.
    pub visibility: Visibility,
    /// The location and data of the resource.
    pub implementation: Implementation<'a>,
}
