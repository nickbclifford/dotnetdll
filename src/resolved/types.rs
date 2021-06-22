use super::{generic::TypeGeneric, members, signature};
use crate::binary::signature::encoded::ArrayShape;

#[derive(Debug)]
pub enum Kind {
    Class,
    Interface,
    ValueType,
}

#[derive(Debug)]
pub enum Accessibility {
    NotPublic,
    Public,
    Nested(members::Accessibility)
}

#[derive(Debug)]
pub enum Layout {
    Automatic,
    Sequential { packing_size: usize, class_size: usize },
    Explicit { packing_size: usize, class_size: usize }
}

#[derive(Debug)]
pub enum StringFormatting {
    ANSI,
    Unicode,
    Automatic,
    Custom(bool, bool) // two-bit mask with non-standard meanings
}

#[derive(Debug)]
pub struct MethodOverride<'a> {
    implementation: &'a members::Method<'a>,
    declaration: &'a members::Method<'a>
}

#[derive(Debug)]
pub struct TypeDefinition<'a> {
    pub name: &'a str,
    pub namespace: Option<&'a str>,
    pub kind: Kind,
    pub fields: Vec<members::Field<'a>>,
    pub properties: Vec<members::Property<'a>>,
    pub methods: Vec<members::Method<'a>>,
    pub events: Vec<members::Event<'a>>,
    pub nested_types: Vec<TypeDefinition<'a>>,
    pub overrides: Vec<MethodOverride<'a>>,
    pub extends: Option<Supertype<'a>>,
    pub implements: Vec<Supertype<'a>>,
    pub generic_parameters: Vec<TypeGeneric<'a>>,
    pub accessibility: Accessibility,
    pub layout: Layout,
    pub abstract_type: bool,
    pub sealed: bool,
    pub special_name: bool,
    pub imported: bool,
    pub serializable: bool,
    pub string_formatting: StringFormatting,
    pub before_field_init: bool,
    pub runtime_special_name: bool,
    // TODO: security
    pub has_security: bool,
    // TODO: exporting
    pub type_forwarder: bool,
}

#[derive(Debug)]
pub struct ExternalTypeReference<'a> {
    pub name: &'a str,
    pub namespace: Option<&'a str>, // TODO: resolution scope
}

#[derive(Debug)]
pub enum UserType<'a> {
    Definition(&'a TypeDefinition<'a>),
    Reference(&'a ExternalTypeReference<'a>),
}

#[derive(Debug)]
pub enum CustomTypeModifier<'a> {
    Optional(UserType<'a>),
    Required(UserType<'a>),
}

#[derive(Debug)]
pub struct GenericInstantiation<'a, CtxBaseType> {
    pub base: UserType<'a>,
    pub parameters: Vec<CtxBaseType>,
}

// the ECMA standard does not necessarily say anything about what TypeSpecs are allowed as supertypes
// however, looking at the stdlib and assemblies shipped with .NET 5, it appears that only GenericInstClass is used
#[derive(Debug)]
pub enum Supertype<'a> {
    User(UserType<'a>),
    Generic(GenericInstantiation<'a, MemberType<'a>>),
}

#[derive(Debug)]
pub enum BaseType<'a, EnclosingType> {
    User(UserType<'a>),
    Generic(GenericInstantiation<'a, EnclosingType>),
    Boolean,
    Char,
    Int8,
    UInt8,
    Int16,
    UInt16,
    Int32,
    UInt32,
    Int64,
    UInt64,
    Float32,
    Float64,
    IntPtr,
    UIntPtr,
    Object,
    String,
    Vector(Option<CustomTypeModifier<'a>>, EnclosingType),
    Array(EnclosingType, ArrayShape),
    ValuePointer(Option<CustomTypeModifier<'a>>, Option<EnclosingType>),
    FunctionPointer(signature::ManagedMethod<'a>),
}

#[derive(Debug)]
pub enum MemberType<'a> {
    Base(Box<BaseType<'a, MemberType<'a>>>),
    TypeGeneric(usize),
}

#[derive(Debug)]
pub enum MethodType<'a> {
    Base(Box<BaseType<'a, MethodType<'a>>>),
    TypeGeneric(usize),
    MethodGeneric(usize),
}
