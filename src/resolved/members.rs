use crate::binary::method;

#[derive(Debug)]
pub struct Field<'a> {
    pub name: &'a str,
    // TODO: flags, modifiers, type
}

#[derive(Debug)]
pub struct Property<'a> {
    pub name: &'a str,
    pub getter: Option<Method<'a>>,
    pub setter: Option<Method<'a>>,
    // TODO: flags, type
}

#[derive(Debug)]
pub struct Method<'a> {
    pub name: &'a str,
    pub body: Option<method::Method>,
    // TODO: flags, signature, parameters
}
