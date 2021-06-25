use super::{
    attribute::{Attribute, SecurityDeclaration},
    body,
    generic::MethodGeneric,
    module::ExternalModuleReference,
    signature,
    types::{CustomTypeModifier, MemberType, MethodType, TypeSource},
};
use crate::binary::signature::kinds::MarshalSpec;

#[derive(Debug)]
pub enum Accessibility {
    CompilerControlled,
    Access(super::Accessibility)
}

#[derive(Debug)]
pub struct Field<'a> {
    pub attributes: Vec<Attribute<'a>>,
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
    pub offset: Option<usize>,
    pub marshal: Option<MarshalSpec>,
    pub start_of_initial_value: Option<&'a [u8]>,
}

#[derive(Debug)]
pub enum FieldReferenceParent<'a> {
    Type(TypeSource<'a, MemberType<'a>>),
    Module(&'a ExternalModuleReference<'a>),
}

#[derive(Debug)]
pub struct ExternalFieldReference<'a> {
    pub attributes: Vec<Attribute<'a>>,
    pub parent: FieldReferenceParent<'a>,
    pub name: &'a str,
    pub return_type: MemberType<'a>,
}

#[derive(Debug)]
pub enum FieldSource<'a> {
    Definition(&'a Field<'a>),
    Reference(&'a ExternalFieldReference<'a>),
}

#[derive(Debug)]
pub struct Property<'a> {
    pub attributes: Vec<Attribute<'a>>,
    pub name: &'a str,
    pub getter: Option<Method<'a>>,
    pub setter: Option<Method<'a>>,
    pub other: Vec<Method<'a>>,
    pub type_modifier: Option<CustomTypeModifier<'a>>,
    pub return_type: MemberType<'a>,
    pub special_name: bool,
    pub runtime_special_name: bool,
    pub default: Option<Constant>,
}

#[derive(Debug)]
pub enum VtableLayout {
    ReuseSlot,
    NewSlot,
}

#[derive(Debug)]
pub struct ParameterMetadata<'a> {
    pub attributes: Vec<Attribute<'a>>,
    pub name: &'a str,
    pub is_in: bool,
    pub is_out: bool,
    pub optional: bool,
    pub default: Option<Constant>,
    pub marshal: Option<MarshalSpec>,
}

#[derive(Debug)]
pub enum BodyFormat {
    IL,
    Native,
    Runtime,
}

#[derive(Debug)]
pub enum BodyManagement {
    Unmanaged,
    Managed,
}

#[derive(Debug)]
pub struct Method<'a> {
    pub attributes: Vec<Attribute<'a>>,
    pub name: &'a str,
    pub body: Option<body::Method<'a>>,
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
    pub pinvoke: Option<PInvoke<'a>>,
    pub runtime_special_name: bool,
    pub security: Option<SecurityDeclaration<'a>>,
    pub require_sec_object: bool,
    pub body_format: BodyFormat,
    pub body_management: BodyManagement,
    pub forward_ref: bool,
    pub preserve_sig: bool,
    pub synchronized: bool,
    pub no_inlining: bool,
    pub no_optimization: bool,
}

#[derive(Debug)]
pub enum CharacterSet {
    NotSpecified,
    Ansi,
    Unicode,
    Auto,
}

#[derive(Debug)]
pub enum UnmanagedCallingConvention {
    Platformapi,
    Cdecl,
    Stdcall,
    Thiscall,
    Fastcall,
}

#[derive(Debug)]
pub struct PInvoke<'a> {
    pub no_mangle: bool,
    pub character_set: CharacterSet,
    pub supports_last_error: bool,
    pub calling_convention: UnmanagedCallingConvention,
    pub import_name: &'a str,
    pub import_scope: ExternalModuleReference<'a>,
}

#[derive(Debug)]
pub enum MethodReferenceParent<'a> {
    Type(TypeSource<'a, MethodType<'a>>),
    Module(&'a ExternalModuleReference<'a>),
    VarargMethod(&'a Method<'a>),
}

#[derive(Debug)]
pub struct ExternalMethodReference<'a> {
    pub attributes: Vec<Attribute<'a>>,
    pub parent: MethodReferenceParent<'a>,
    pub name: &'a str,
    pub signature: signature::ManagedMethod<'a>,
}

#[derive(Debug)]
pub enum UserMethod<'a> {
    Definition(&'a Method<'a>),
    Reference(&'a ExternalMethodReference<'a>),
}

impl<'a> UserMethod<'a> {
    pub fn signature(&self) -> &signature::ManagedMethod<'a> {
        match self {
            UserMethod::Definition(d) => &d.signature,
            UserMethod::Reference(r) => &r.signature,
        }
    }
}

#[derive(Debug)]
pub struct GenericMethodInstantiation<'a> {
    pub attributes: Vec<Attribute<'a>>,
    pub base: UserMethod<'a>,
    pub parameters: Vec<MethodType<'a>>,
}

#[derive(Debug)]
pub enum MethodSource<'a> {
    User(UserMethod<'a>),
    Generic(GenericMethodInstantiation<'a>),
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
    Null,
}

#[derive(Debug)]
pub struct Event<'a> {
    pub attributes: Vec<Attribute<'a>>,
    pub name: &'a str,
    pub delegate_type: MemberType<'a>, // standard says this can be null, but that doesn't make any sense
    pub add_listener: Method<'a>,
    pub remove_listener: Method<'a>,
    pub raise_event: Option<Method<'a>>,
    pub other: Vec<Method<'a>>,
    pub special_name: bool,
    pub runtime_special_name: bool,
}
