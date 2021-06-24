use super::attribute::Attribute;

#[derive(Debug)]
pub struct Module<'a> {
    pub attributes: Vec<Attribute<'a>>,
    pub name: &'a str,
    pub mvid: [u8; 16],
}

#[derive(Debug)]
pub struct ExternalModuleReference<'a> {
    pub attributes: Vec<Attribute<'a>>,
    pub name: &'a str,
}

#[derive(Debug)]
pub struct File<'a> {
    pub attributes: Vec<Attribute<'a>>,
    pub has_metadata: bool,
    pub name: &'a str,
    pub hash_value: &'a [u8],
}
