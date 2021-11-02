use super::attribute::Attribute;

#[derive(Debug, Copy, Clone)]
pub enum Implementation {
    File(crate::resolution::FileIndex),
    Assembly(crate::resolution::AssemblyRefIndex),
}

#[derive(Debug, Copy, Clone)]
pub enum Visibility {
    Public,
    Private,
}

#[derive(Debug, Clone)]
pub struct ManifestResource<'a> {
    pub attributes: Vec<Attribute<'a>>,
    pub offset: usize,
    pub name: &'a str,
    pub visibility: Visibility,
    pub implementation: Option<Implementation>,
}
