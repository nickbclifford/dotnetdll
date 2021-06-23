#[derive(Debug)]
pub struct Module<'a> {
    pub name: &'a str,
    pub mvid: [u8; 16],
}

#[derive(Debug)]
pub struct ExternalModuleReference<'a> {
    pub name: &'a str,
}

#[derive(Debug)]
pub struct File<'a> {
    pub has_metadata: bool,
    pub name: &'a str,
    pub hash_value: &'a [u8],
}
