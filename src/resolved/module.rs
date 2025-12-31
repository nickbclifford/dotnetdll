use super::attribute::Attribute;
use std::borrow::Cow;

/// Represents the identity and metadata of the current module.
///
/// Every .NET DLL contains exactly one module (ECMA-335, II.22.30).
#[derive(Debug, Clone)]
pub struct Module<'a> {
    /// All attributes present on the module declaration.
    pub attributes: Vec<Attribute<'a>>,
    /// Name of the module (typically the filename of the DLL).
    pub name: Cow<'a, str>,
    /// Module version identifier (GUID).
    pub mvid: [u8; 16],
}
impl<'a> Module<'a> {
    /// Creates a new `Module` with the specified name and default metadata.
    pub fn new(name: impl Into<Cow<'a, str>>) -> Self {
        Self {
            attributes: vec![],
            name: name.into(),
            mvid: [0; 16],
        }
    }
}

/// A reference to an external module within the same assembly.
///
/// See ECMA-335, II.22.31 (page 237) for more information.
#[derive(Debug, Clone)]
pub struct ExternalModuleReference<'a> {
    /// All attributes present on the module reference.
    pub attributes: Vec<Attribute<'a>>,
    /// Name of the external module.
    pub name: Cow<'a, str>,
}
impl<'a> ExternalModuleReference<'a> {
    /// Creates a new `ExternalModuleReference` with the specified name and default metadata.
    pub fn new(name: impl Into<Cow<'a, str>>) -> Self {
        Self {
            attributes: vec![],
            name: name.into(),
        }
    }
}

/// A constituent file of the assembly.
///
/// See ECMA-335, II.22.19 (page 228) for more information.
#[derive(Debug, Clone)]
pub struct File<'a> {
    /// All attributes present on the file declaration.
    pub attributes: Vec<Attribute<'a>>,
    /// If true, the file contains CLI metadata.
    pub has_metadata: bool,
    /// Name of the file.
    pub name: Cow<'a, str>,
    /// Hash value of the file's content.
    pub hash_value: Cow<'a, [u8]>,
}
