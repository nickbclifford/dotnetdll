use super::{assembly, attribute::Attribute, module};

#[derive(Debug)]
pub enum Implementation<'a> {
    File(&'a module::File<'a>),
    Assembly(assembly::ExternalAssemblyReference<'a>),
}

#[derive(Debug)]
pub enum Visibility {
    Public,
    Private,
}

#[derive(Debug)]
pub struct ManifestResource<'a> {
    pub attributes: Vec<Attribute<'a>>,
    pub offset: usize,
    pub name: &'a str,
    pub visibility: Visibility,
    pub implementation: Implementation<'a>,
}
