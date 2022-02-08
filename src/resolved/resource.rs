use super::attribute::Attribute;
use crate::resolution::{AssemblyRefIndex, FileIndex};
use std::borrow::Cow;

#[derive(Debug, Clone)]
pub enum Implementation<'a> {
    File { location: FileIndex, offset: usize },
    Assembly { location: AssemblyRefIndex, offset: usize },
    CurrentFile(Cow<'a, [u8]>),
}

#[derive(Debug, Copy, Clone)]
pub enum Visibility {
    Public,
    Private,
}

#[derive(Debug, Clone)]
pub struct ManifestResource<'a> {
    pub attributes: Vec<Attribute<'a>>,
    pub name: &'a str,
    pub visibility: Visibility,
    pub implementation: Implementation<'a>,
}
