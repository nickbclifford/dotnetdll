use super::{assembly, attribute::Attribute, module};
use std::rc::Rc;

#[derive(Debug)]
pub enum Implementation<'a> {
    File(Rc<module::File<'a>>),
    Assembly(Rc<assembly::ExternalAssemblyReference<'a>>),
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
    pub implementation: Option<Implementation<'a>>,
}
