use super::{
    signature,
    types::{CustomTypeModifier, MemberType},
};
use crate::binary::method;

#[derive(Debug)]
pub struct Field<'a> {
    pub name: &'a str,
    pub type_modifier: Option<CustomTypeModifier<'a>>,
    pub return_type: MemberType<'a>, // TODO: flags
}

#[derive(Debug)]
pub struct Property<'a> {
    pub name: &'a str,
    pub getter: Option<Method<'a>>,
    pub setter: Option<Method<'a>>,
    pub type_modifier: Option<CustomTypeModifier<'a>>,
    pub return_type: MemberType<'a>, // TODO: flags
}

#[derive(Debug)]
pub struct Method<'a> {
    pub name: &'a str,
    pub body: Option<method::Method>,
    pub signature: signature::ManagedMethod<'a>, // TODO: flags
}
