use super::{
    attribute::{Attribute, SecurityDeclaration},
    body,
    generic::MethodGeneric,
    module::ExternalModuleReference,
    signature,
    types::{CustomTypeModifier, MemberType, MethodType, TypeDefinition, TypeSource},
};
use crate::binary::signature::kinds::MarshalSpec;

use std::fmt::{Display, Formatter};

macro_rules! name_display {
    ($i:ty) => {
        impl Display for $i {
            fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
                write!(f, "{}", self.name)
            }
        }
    };
}

#[derive(Debug)]
pub enum Accessibility {
    CompilerControlled,
    Access(super::Accessibility),
}

#[derive(Debug)]
pub struct Field<'a> {
    pub attributes: Vec<Attribute<'a>>,
    pub name: &'a str,
    pub type_modifier: Option<CustomTypeModifier>,
    pub return_type: MemberType,
    pub accessibility: Accessibility,
    pub static_member: bool,
    pub init_only: bool,
    pub literal: bool,
    pub default: Option<Constant>,
    pub not_serialized: bool,
    pub special_name: bool,
    pub pinvoke: bool,
    pub runtime_special_name: bool,
    pub offset: Option<usize>,
    pub marshal: Option<MarshalSpec>,
    pub start_of_initial_value: Option<&'a [u8]>,
}
name_display!(Field<'_>);

#[derive(Debug)]
pub enum FieldReferenceParent<'a> {
    Type(TypeSource<MemberType>),
    Module(&'a ExternalModuleReference<'a>),
}

#[derive(Debug)]
pub struct ExternalFieldReference<'a> {
    pub attributes: Vec<Attribute<'a>>,
    pub parent: FieldReferenceParent<'a>,
    pub name: &'a str,
    pub return_type: MemberType,
}
name_display!(ExternalFieldReference<'_>);

#[derive(Debug)]
pub enum FieldSource<'a> {
    Definition {
        parent: &'a TypeDefinition<'a>,
        field: &'a Field<'a>,
    },
    Reference(&'a ExternalFieldReference<'a>),
}
impl Display for FieldSource<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        use FieldSource::*;

        match *self {
            Definition { field, .. } => write!(f, "{}", field),
            Reference(r) => write!(f, "{}", r),
        }
    }
}

#[derive(Debug)]
pub struct Property<'a> {
    pub attributes: Vec<Attribute<'a>>,
    pub name: &'a str,
    pub getter: Option<Method<'a>>,
    pub setter: Option<Method<'a>>,
    pub other: Vec<Method<'a>>,
    pub type_modifier: Option<CustomTypeModifier>,
    pub return_type: MemberType,
    pub special_name: bool,
    pub runtime_special_name: bool,
    pub default: Option<Constant>,
}
name_display!(Property<'_>);

#[derive(Debug)]
pub enum VtableLayout {
    ReuseSlot,
    NewSlot,
}

#[derive(Debug, Clone)]
pub struct ParameterMetadata<'a> {
    pub attributes: Vec<Attribute<'a>>,
    pub name: &'a str,
    pub is_in: bool,
    pub is_out: bool,
    pub optional: bool,
    pub default: Option<Constant>,
    pub marshal: Option<MarshalSpec>,
}
name_display!(ParameterMetadata<'_>);

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
    pub signature: signature::ManagedMethod,
    pub accessibility: Accessibility,
    pub generic_parameters: Vec<MethodGeneric<'a>>,
    pub parameter_metadata: Vec<Option<ParameterMetadata<'a>>>,
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
name_display!(Method<'_>);

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
    Type(TypeSource<MethodType>),
    Module(&'a ExternalModuleReference<'a>),
    VarargMethod(&'a Method<'a>),
}

#[derive(Debug)]
pub struct ExternalMethodReference<'a> {
    pub attributes: Vec<Attribute<'a>>,
    pub parent: MethodReferenceParent<'a>,
    pub name: &'a str,
    pub signature: signature::ManagedMethod,
}
name_display!(ExternalMethodReference<'_>);

#[derive(Debug, Copy, Clone)]
pub enum UserMethod<'a> {
    Definition {
        parent: &'a TypeDefinition<'a>,
        method: &'a Method<'a>,
    },
    Reference(&'a ExternalMethodReference<'a>),
}
impl Display for UserMethod<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        use UserMethod::*;

        match *self {
            Definition { method, .. } => write!(f, "{}", method),
            Reference(r) => write!(f, "{}", r),
        }
    }
}
impl UserMethod<'_> {
    pub fn signature(&self) -> &signature::ManagedMethod {
        match self {
            UserMethod::Definition { method: d, .. } => &d.signature,
            UserMethod::Reference(r) => &r.signature,
        }
    }
}

#[derive(Debug)]
pub struct GenericMethodInstantiation<'a> {
    pub attributes: Vec<Attribute<'a>>,
    pub base: UserMethod<'a>,
    pub parameters: Vec<MethodType>,
}

#[derive(Debug)]
pub enum MethodSource<'a> {
    User(UserMethod<'a>),
    Generic(GenericMethodInstantiation<'a>),
}

#[derive(Debug, Clone)]
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
    pub delegate_type: MemberType, // standard says this can be null, but that doesn't make any sense
    pub add_listener: Method<'a>,
    pub remove_listener: Method<'a>,
    pub raise_event: Option<Method<'a>>,
    pub other: Vec<Method<'a>>,
    pub special_name: bool,
    pub runtime_special_name: bool,
}
name_display!(Event<'_>);
