use super::{
    assembly, attribute::SecurityDeclaration, generic::TypeGeneric, members, module, signature,
};
use crate::binary::signature::encoded::ArrayShape;

#[derive(Debug)]
pub enum Kind {
    Class,
    Interface,
}

#[derive(Debug)]
pub enum Accessibility {
    NotPublic,
    Public,
    Nested(members::Accessibility),
}

#[derive(Debug)]
pub enum Layout {
    Automatic,
    Sequential {
        packing_size: usize,
        class_size: usize,
    },
    Explicit {
        class_size: usize,
    },
}

#[derive(Debug)]
pub enum StringFormatting {
    ANSI,
    Unicode,
    Automatic,
    Custom(bool, bool), // two-bit mask with non-standard meanings
}

#[derive(Debug)]
pub struct MethodOverride<'a> {
    implementation: &'a members::Method<'a>,
    declaration: &'a members::Method<'a>,
}

macro_rules! type_name_impl {
    ($i:ty) => {
        impl $i {
            pub fn type_name(&self) -> String {
                match self.namespace {
                    Some(ns) => format!("{}.{}", ns, self.name),
                    None => self.name.to_string(),
                }
            }
        }
    };
}

#[derive(Debug)]
pub struct TypeFlags {
    pub accessibility: Accessibility,
    pub layout: Layout,
    pub kind: Kind,
    pub abstract_type: bool,
    pub sealed: bool,
    pub special_name: bool,
    pub imported: bool,
    pub serializable: bool,
    pub string_formatting: StringFormatting,
    pub before_field_init: bool,
    pub runtime_special_name: bool,
}

#[derive(Debug)]
pub struct TypeDefinition<'a> {
    pub name: &'a str,
    pub namespace: Option<&'a str>,
    pub fields: Vec<members::Field<'a>>,
    pub properties: Vec<members::Property<'a>>,
    pub methods: Vec<members::Method<'a>>,
    pub events: Vec<members::Event<'a>>,
    pub nested_types: Vec<TypeDefinition<'a>>,
    pub overrides: Vec<MethodOverride<'a>>,
    pub extends: Option<TypeSource<'a, MemberType<'a>>>,
    pub implements: Vec<TypeSource<'a, MemberType<'a>>>,
    pub generic_parameters: Vec<TypeGeneric<'a>>,
    pub flags: TypeFlags,
    pub security: Option<SecurityDeclaration<'a>>,
}

#[derive(Debug)]
pub enum ResolutionScope<'a> {
    Nested(Box<ExternalTypeReference<'a>>),
    ExternalModule(module::ExternalModuleReference<'a>),
    CurrentModule(&'a module::Module<'a>), // TODO: reference?
    Assembly(assembly::ExternalAssemblyReference<'a>),
    Exported(&'a ExportedType<'a>),
}

#[derive(Debug)]
pub struct ExternalTypeReference<'a> {
    pub name: &'a str,
    pub namespace: Option<&'a str>,
    pub scope: ResolutionScope<'a>,
}

#[derive(Debug)]
pub enum TypeImplementation<'a> {
    Nested(&'a ExportedType<'a>),
    ModuleFile {
        type_def_idx: usize,
        file: &'a module::File<'a>,
    },
    TypeForwarder(assembly::ExternalAssemblyReference<'a>),
}

#[derive(Debug)]
pub struct ExportedType<'a> {
    pub flags: TypeFlags,
    pub name: &'a str,
    pub namespace: Option<&'a str>,
    pub implementation: TypeImplementation<'a>,
}

type_name_impl!(TypeDefinition<'_>);
type_name_impl!(ExternalTypeReference<'_>);
type_name_impl!(ExportedType<'_>);

#[derive(Debug)]
pub enum UserType<'a> {
    Definition(&'a TypeDefinition<'a>),
    Reference(ExternalTypeReference<'a>),
}

impl UserType<'_> {
    pub fn type_name(&self) -> String {
        match self {
            UserType::Definition(t) => t.type_name(),
            UserType::Reference(t) => t.type_name(),
        }
    }
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
pub enum TypeSource<'a, EnclosingType> {
    User(UserType<'a>),
    Generic(GenericInstantiation<'a, EnclosingType>),
}

#[derive(Debug)]
pub enum BaseType<'a, EnclosingType> {
    Type(TypeSource<'a, EnclosingType>),
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

#[derive(Debug)]
pub enum LocalVariable<'a> {
    TypedReference,
    Variable {
        custom_modifier: Option<CustomTypeModifier<'a>>,
        pinned: bool,
        by_ref: bool,
        var_type: MethodType<'a>,
    },
}

pub trait Resolver {
    type Error: std::error::Error;
    fn find_type<'a>(&self, name: &str) -> Result<&'a TypeDefinition<'a>, Self::Error>;
}
