use super::{
    generic::MethodGeneric,
    signature,
    types::{CustomTypeModifier, MemberType},
};
use crate::binary::method;

#[derive(Debug)]
pub enum Accessibility {
    CompilerControlled,
    Private,
    PrivateProtected,  // FamANDAssem
    Internal,          // Assem
    Protected,         // Family
    ProtectedInternal, // FamORAssem
    Public
}

#[derive(Debug)]
pub struct Field<'a> {
    pub name: &'a str,
    pub type_modifier: Option<CustomTypeModifier<'a>>,
    pub return_type: MemberType<'a>,
    pub accessibility: Accessibility,
    pub static_member: bool,
    pub init_only: bool,
    pub constant: bool,
    pub default: Option<Constant>,
    pub not_serialized: bool,
    pub special_name: bool,
}

#[derive(Debug)]
pub struct Property<'a> {
    pub name: &'a str,
    pub getter: Option<Method<'a>>,
    pub setter: Option<Method<'a>>,
    pub type_modifier: Option<CustomTypeModifier<'a>>,
    pub return_type: MemberType<'a>,
    pub special_name: bool,
    pub runtime_special_name: bool,
    pub default: Option<Constant>,
}

#[derive(Debug)]
pub enum VtableLayout {
    ReuseSlot,
    NewSlot
}

#[derive(Debug)]
pub struct ParameterMetadata<'a> {
    pub name: &'a str,
    pub is_in: bool,
    pub is_out: bool,
    pub optional: bool,
    pub default: Option<Constant>,
    pub has_field_marshal: bool
}

#[derive(Debug)]
pub struct Method<'a> {
    pub name: &'a str,
    pub body: Option<method::Method>,
    pub signature: signature::ManagedMethod<'a>,
    pub accessibility: Accessibility,
    pub generic_parameters: Vec<MethodGeneric<'a>>,
    pub parameter_metadata: Vec<ParameterMetadata<'a>>,
    pub static_member: bool,
    pub sealed: bool,
    pub virtual_member: bool,
    pub hide_by_sig: bool,
    pub vtable_layout: VtableLayout,
    pub strict: bool,
    pub abstract_member: bool,
    pub special_name: bool,
    pub pinvoke: bool,
    pub runtime_special_name: bool,
    // TODO: security
    pub has_security: bool,
    pub require_sec_object: bool
    // TODO: implementation, semantics
}

#[derive(Debug)]
pub enum Constant {
    Boolean(bool),
    Char(char),
    Int8(i8),
    UInt8(u8),
    Int16(i16),
    UInt16(u16),
    Int32(i32),
    UInt32(u32),
    Int64(i64),
    UInt64(u64),
    Float32(f32),
    Float64(f64),
    String(String), // UTF16, which we parse into an owned String
    Null
}
