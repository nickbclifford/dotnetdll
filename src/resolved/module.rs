use super::attribute::Attribute;
use std::borrow::Cow;

#[derive(Debug, Clone)]
pub struct Module<'a> {
    pub attributes: Vec<Attribute<'a>>,
    pub name: Cow<'a, str>,
    pub mvid: [u8; 16],
}
impl<'a> Module<'a> {
    pub fn new(name: impl Into<Cow<'a, str>>) -> Self {
        Self {
            attributes: vec![],
            name: name.into(),
            mvid: [0; 16],
        }
    }
}

#[derive(Debug, Clone)]
pub struct ExternalModuleReference<'a> {
    pub attributes: Vec<Attribute<'a>>,
    pub name: Cow<'a, str>,
}
impl<'a> ExternalModuleReference<'a> {
    pub fn new(name: impl Into<Cow<'a, str>>) -> Self {
        Self {
            attributes: vec![],
            name: name.into(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct File<'a> {
    pub attributes: Vec<Attribute<'a>>,
    pub has_metadata: bool,
    pub name: Cow<'a, str>,
    pub hash_value: Cow<'a, [u8]>,
}
