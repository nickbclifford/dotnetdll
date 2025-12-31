use super::attribute::{Attribute, SecurityDeclaration};
use std::borrow::Cow;

/// Metadata flags associated with an [`Assembly`].
///
/// See ECMA-335, II.23.1.2 (page 250) for more information.
#[derive(Debug, Default, Copy, Clone)]
pub struct Flags {
    /// If true, the `public_key` field contains the full public key.
    /// Otherwise, it contains a public key token.
    pub has_full_public_key: bool,
    /// If true, the assembly can be retargeted at runtime to a different version.
    pub retargetable: bool,
    /// If true, the JIT compiler should not optimize the code in this assembly.
    pub disable_jit_optimizer: bool,
    /// If true, the JIT compiler should include tracking information for debugging.
    pub enable_jit_tracking: bool,
}

impl Flags {
    /// Creates a new `Flags` struct from a raw bitmask.
    pub fn new(bitmask: u32) -> Flags {
        Flags {
            has_full_public_key: check_bitmask!(bitmask, 0x0001),
            retargetable: check_bitmask!(bitmask, 0x0100),
            disable_jit_optimizer: check_bitmask!(bitmask, 0x4000),
            enable_jit_tracking: check_bitmask!(bitmask, 0x8000),
        }
    }

    /// Converts the `Flags` struct back into a raw bitmask.
    pub fn to_mask(self) -> u32 {
        build_bitmask!(self,
            has_full_public_key => 0x0001,
            retargetable => 0x0100,
            disable_jit_optimizer => 0x4000,
            enable_jit_tracking => 0x8000)
    }
}

/// Represents the version of an assembly or assembly reference.
#[derive(Debug, Default, Copy, Clone)]
pub struct Version {
    pub major: u16,
    pub minor: u16,
    pub build: u16,
    pub revision: u16,
}
impl Version {
    /// A version representing 0.0.0.0.
    pub const ZERO: Self = Self {
        major: 0,
        minor: 0,
        build: 0,
        revision: 0,
    };
}

/// Specifies the hashing algorithm used for files within the assembly.
#[derive(Debug, Copy, Clone)]
pub enum HashAlgorithm {
    None,
    ReservedMD5,
    SHA1,
}

/// Represents the identity and metadata of the current assembly.
///
/// See ECMA-335, II.22.2 (page 208) for more information.
#[derive(Debug, Clone)]
pub struct Assembly<'a> {
    /// All attributes present on the assembly declaration.
    pub attributes: Vec<Attribute<'a>>,
    /// Hashing algorithm used for the assembly's constituent files.
    pub hash_algorithm: HashAlgorithm,
    /// Version of the assembly.
    pub version: Version,
    /// Metadata flags for the assembly.
    pub flags: Flags,
    /// Public key of the assembly's originator, if any.
    pub public_key: Option<Cow<'a, [u8]>>,
    /// Simple name of the assembly.
    pub name: Cow<'a, str>,
    /// Culture (locale) of the assembly, if any.
    pub culture: Option<Cow<'a, str>>,
    /// Runtime security metadata associated with the assembly.
    pub security: Option<SecurityDeclaration<'a>>,
}
impl<'a> Assembly<'a> {
    /// Creates a new `Assembly` with the specified name and default metadata.
    pub fn new(name: impl Into<Cow<'a, str>>) -> Self {
        Self {
            attributes: vec![],
            hash_algorithm: HashAlgorithm::None,
            version: Version::ZERO,
            flags: Flags {
                has_full_public_key: false,
                retargetable: false,
                disable_jit_optimizer: false,
                enable_jit_tracking: false,
            },
            public_key: None,
            name: name.into(),
            culture: None,
            security: None,
        }
    }
}

/// A reference to an external assembly that this assembly depends on.
///
/// See ECMA-335, II.22.5 (page 211) for more information.
#[derive(Debug, Clone)]
pub struct ExternalAssemblyReference<'a> {
    /// All attributes present on the assembly reference declaration.
    pub attributes: Vec<Attribute<'a>>,
    /// Version of the external assembly being referenced.
    pub version: Version,
    /// If true, the `public_key_or_token` field contains the full public key.
    pub has_full_public_key: bool,
    /// Public key or public key token of the external assembly.
    pub public_key_or_token: Option<Cow<'a, [u8]>>,
    /// Simple name of the external assembly.
    pub name: Cow<'a, str>,
    /// Culture (locale) of the external assembly, if any.
    pub culture: Option<Cow<'a, str>>,
    /// Hash value of the external assembly's manifest file, if any.
    pub hash_value: Option<Cow<'a, [u8]>>,
}
impl<'a> ExternalAssemblyReference<'a> {
    /// Creates a new `ExternalAssemblyReference` with the specified name and default metadata.
    pub fn new(name: impl Into<Cow<'a, str>>) -> Self {
        Self {
            attributes: vec![],
            version: Version::ZERO,
            has_full_public_key: false,
            public_key_or_token: None,
            name: name.into(),
            culture: None,
            hash_value: None,
        }
    }
}
