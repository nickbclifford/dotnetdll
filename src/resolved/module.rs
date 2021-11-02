use super::attribute::Attribute;

#[derive(Debug, Clone)]
pub struct Module<'a> {
    pub attributes: Vec<Attribute<'a>>,
    pub name: &'a str,
    pub mvid: [u8; 16],
}

#[derive(Debug, Clone)]
pub struct ExternalModuleReference<'a> {
    pub attributes: Vec<Attribute<'a>>,
    pub name: &'a str,
}

#[derive(Debug, Clone)]
pub struct File<'a> {
    pub attributes: Vec<Attribute<'a>>,
    pub has_metadata: bool,
    pub name: &'a str,
    pub hash_value: &'a [u8],
}
