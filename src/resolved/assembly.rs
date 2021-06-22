#[derive(Debug)]
pub struct Flags {
    pub has_public_key: bool,
    pub retargetable: bool,
    pub disable_jit_optimizer: bool,
    pub enable_jit_tracking: bool,
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
    pub hash_algorithm: HashAlgorithm,
    pub version: Version,
    pub flags: Flags,
    pub public_key: Option<&'a [u8]>,
    pub name: &'a str,
    pub culture: Option<&'a str>,
}

#[derive(Debug)]
pub struct ExternalAssemblyReference<'a> {
    pub version: Version,
    pub flags: Flags,
    pub public_key_or_token: Option<&'a [u8]>,
    pub name: &'a str,
    pub culture: Option<&'a str>,
    pub hash_value: Option<&'a [u8]>,
}
