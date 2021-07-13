use super::{assembly, attribute::Attribute, module};
use std::{cell::RefCell, rc::Rc};

#[derive(Debug)]
pub enum Implementation<'a> {
    File(Rc<RefCell<module::File<'a>>>),
    Assembly(Rc<RefCell<assembly::ExternalAssemblyReference<'a>>>),
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
