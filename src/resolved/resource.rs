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

// TODO: a null implementation means offset in the current file
// change from Option<Implementation> to an Implementation that contains the bytes to insert?

#[derive(Debug, Clone)]
pub struct ManifestResource<'a> {
    pub attributes: Vec<Attribute<'a>>,
    pub offset: usize,
    pub name: &'a str,
    pub visibility: Visibility,
    pub implementation: Option<Implementation>,
}
