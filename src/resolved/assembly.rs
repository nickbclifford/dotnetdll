use super::attribute::{Attribute, SecurityDeclaration};

#[derive(Debug)]
pub struct Flags {
    pub has_public_key: bool,
    pub retargetable: bool,
    pub disable_jit_optimizer: bool,
    pub enable_jit_tracking: bool,
}

impl Flags {
    pub fn new(bitmask: u32) -> Flags {
        Flags {
            has_public_key: check_bitmask!(bitmask, 0x0001),
            retargetable: check_bitmask!(bitmask, 0x0100),
            disable_jit_optimizer: check_bitmask!(bitmask, 0x4000),
            enable_jit_tracking: check_bitmask!(bitmask, 0x8000),
        }
    }
}

#[derive(Debug)]
pub struct Version {
    pub major: u16,
    pub minor: u16,
    pub build: u16,
    pub revision: u16,
}

#[derive(Debug)]
pub enum HashAlgorithm {
    None,
    ReservedMD5,
    SHA1,
}

#[derive(Debug)]
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

#[derive(Debug)]
pub struct ExternalAssemblyReference<'a> {
    pub attributes: Vec<Attribute<'a>>,
    pub version: Version,
    pub flags: Flags,
    pub public_key_or_token: Option<&'a [u8]>,
    pub name: &'a str,
    pub culture: Option<&'a str>,
    pub hash_value: Option<&'a [u8]>,
}