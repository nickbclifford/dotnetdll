use super::attribute::{Attribute, SecurityDeclaration};

#[derive(Debug, Default, Copy, Clone)]
pub struct Flags {
    pub has_full_public_key: bool,
    pub retargetable: bool,
    pub disable_jit_optimizer: bool,
    pub enable_jit_tracking: bool,
}

impl Flags {
    pub fn new(bitmask: u32) -> Flags {
        Flags {
            has_full_public_key: check_bitmask!(bitmask, 0x0001),
            retargetable: check_bitmask!(bitmask, 0x0100),
            disable_jit_optimizer: check_bitmask!(bitmask, 0x4000),
            enable_jit_tracking: check_bitmask!(bitmask, 0x8000),
        }
    }

    pub fn to_mask(self) -> u32 {
        build_bitmask!(self,
            has_full_public_key => 0x0001,
            retargetable => 0x0100,
            disable_jit_optimizer => 0x4000,
            enable_jit_tracking => 0x8000)
    }
}

#[derive(Debug, Default, Copy, Clone)]
pub struct Version {
    pub major: u16,
    pub minor: u16,
    pub build: u16,
    pub revision: u16,
}
impl Version {
    pub const ZERO: Self = Self {
        major: 0,
        minor: 0,
        build: 0,
        revision: 0
    };
}

#[derive(Debug, Copy, Clone)]
pub enum HashAlgorithm {
    None,
    ReservedMD5,
    SHA1,
}

#[derive(Debug, Clone)]
pub struct Assembly<'a> {
    pub attributes: Vec<Attribute<'a>>,
    pub hash_algorithm: HashAlgorithm,
    pub version: Version,
    pub flags: Flags,
    pub public_key: Option<&'a [u8]>,
    pub name: &'a str,
    pub culture: Option<&'a str>,
    pub security: Option<SecurityDeclaration<'a>>,
}
impl<'a> Assembly<'a> {
    pub const fn new(name: &'a str) -> Self {
        Self {
            attributes: vec![],
            hash_algorithm: HashAlgorithm::None,
            version: Version::ZERO,
            flags: Flags {
                has_full_public_key: false,
                retargetable: false,
                disable_jit_optimizer: false,
                enable_jit_tracking: false
            },
            public_key: None,
            name,
            culture: None,
            security: None
        }
    }
}

#[derive(Debug, Clone)]
pub struct ExternalAssemblyReference<'a> {
    pub attributes: Vec<Attribute<'a>>,
    pub version: Version,
    pub has_full_public_key: bool,
    pub public_key_or_token: Option<&'a [u8]>,
    pub name: &'a str,
    pub culture: Option<&'a str>,
    pub hash_value: Option<&'a [u8]>,
}
impl<'a> ExternalAssemblyReference<'a> {
    pub const fn new(name: &'a str) -> Self {
        Self {
            attributes: vec![],
            version: Version::ZERO,
            has_full_public_key: false,
            public_key_or_token: None,
            name,
            culture: None,
            hash_value: None
        }
    }
}
