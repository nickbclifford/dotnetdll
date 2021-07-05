use super::{
    assembly,
    attribute::{Attribute, SecurityDeclaration},
    generic::TypeGeneric,
    members, module, signature,
};
use crate::{binary::signature::encoded::ArrayShape, dll::Resolution};

use std::rc::Rc;

#[derive(Debug)]
pub enum Kind {
    Class,
    Interface,
}

#[derive(Debug)]
pub enum Accessibility {
    NotPublic,
    Public,
    Nested(super::Accessibility),
}

#[derive(Debug)]
pub struct SequentialLayout {
    pub packing_size: usize,
    pub class_size: usize,
}

#[derive(Debug)]
pub struct ExplicitLayout {
    pub class_size: usize,
}

#[derive(Debug)]
pub enum Layout {
    Automatic,
    Sequential(Option<SequentialLayout>),
    Explicit(Option<ExplicitLayout>),
}

#[derive(Debug)]
pub enum StringFormatting {
    ANSI,
    Unicode,
    Automatic,
    Custom(u32),
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

impl TypeFlags {
    pub fn new(bitmask: u32, layout: Layout) -> TypeFlags {
        use Accessibility::*;

        TypeFlags {
            accessibility: match bitmask & 0x7 {
                0x0 => NotPublic,
                0x1 => Public,
                0x2 => Nested(super::Accessibility::Public),
                0x3 => Nested(super::Accessibility::Private),
                0x4 => Nested(super::Accessibility::Protected),
                0x5 => Nested(super::Accessibility::Internal),
                0x6 => Nested(super::Accessibility::PrivateProtected),
                0x7 => Nested(super::Accessibility::ProtectedInternal),
                _ => unreachable!(),
            },
            layout,
            kind: match bitmask & 0x20 {
                0x00 => Kind::Class,
                0x20 => Kind::Interface,
                _ => unreachable!(),
            },
            abstract_type: check_bitmask!(bitmask, 0x80),
            sealed: check_bitmask!(bitmask, 0x100),
            special_name: check_bitmask!(bitmask, 0x400),
            imported: check_bitmask!(bitmask, 0x1000),
            serializable: check_bitmask!(bitmask, 0x2000),
            string_formatting: match bitmask & 0x30000 {
                0x00000 => StringFormatting::ANSI,
                0x10000 => StringFormatting::Unicode,
                0x20000 => StringFormatting::Automatic,
                0x30000 => StringFormatting::Custom(bitmask & 0xC00000),
                _ => unreachable!(),
            },
            before_field_init: check_bitmask!(bitmask, 0x1000000),
            runtime_special_name: check_bitmask!(bitmask, 0x800),
        }
    }
}

#[derive(Debug)]
pub struct TypeDefinition<'a> {
    pub attributes: Vec<Attribute<'a>>,
    pub name: &'a str,
    pub namespace: Option<&'a str>,
    pub fields: Vec<members::Field<'a>>,
    pub properties: Vec<members::Property<'a>>,
    pub methods: Vec<members::Method<'a>>,
    pub events: Vec<members::Event<'a>>,
    pub nested_types: Vec<TypeDefinition<'a>>,
    pub overrides: Vec<MethodOverride<'a>>,
    pub extends: Option<TypeSource<MemberType>>,
    pub implements: Vec<(Attribute<'a>, TypeSource<MemberType>)>,
    pub generic_parameters: Vec<TypeGeneric<'a>>,
    pub flags: TypeFlags,
    pub security: Option<SecurityDeclaration<'a>>,
}

#[derive(Debug)]
pub enum ResolutionScope<'a> {
    Nested(usize),
    ExternalModule(Rc<module::ExternalModuleReference<'a>>),
    CurrentModule,
    Assembly(Rc<assembly::ExternalAssemblyReference<'a>>),
    Exported(Rc<ExportedType<'a>>),
}

#[derive(Debug)]
pub struct ExternalTypeReference<'a> {
    pub attributes: Vec<Attribute<'a>>,
    pub name: &'a str,
    pub namespace: Option<&'a str>,
    pub scope: ResolutionScope<'a>,
}

#[derive(Debug)]
pub enum TypeImplementation<'a> {
    Nested(usize),
    ModuleFile {
        type_def_idx: usize,
        file: Rc<module::File<'a>>,
    },
    TypeForwarder(Rc<assembly::ExternalAssemblyReference<'a>>),
}

#[derive(Debug)]
pub struct ExportedType<'a> {
    pub attributes: Vec<Attribute<'a>>,
    pub flags: TypeFlags,
    pub name: &'a str,
    pub namespace: Option<&'a str>,
    pub implementation: TypeImplementation<'a>,
}

type_name_impl!(TypeDefinition<'_>);
type_name_impl!(ExternalTypeReference<'_>);
type_name_impl!(ExportedType<'_>);

#[derive(Debug, Clone)]
pub enum UserType {
    Definition(usize),
    Reference(usize),
}

impl UserType {
    pub fn type_name(&self, r: &Resolution) -> String {
        match self {
            UserType::Definition(idx) => r.type_definitions[*idx].type_name(),
            UserType::Reference(idx) => r.type_references[*idx].type_name(),
        }
    }
}

#[derive(Debug, Clone)]
pub enum CustomTypeModifier {
    Optional(UserType),
    Required(UserType),
}

#[derive(Debug, Clone)]
pub struct GenericInstantiation<CtxBaseType> {
    pub base: UserType,
    pub parameters: Vec<CtxBaseType>,
}

// the ECMA standard does not necessarily say anything about what TypeSpecs are allowed as supertypes
// however, looking at the stdlib and assemblies shipped with .NET 5, it appears that only GenericInstClass is used
#[derive(Debug, Clone)]
pub enum TypeSource<EnclosingType> {
    User(UserType),
    Generic(GenericInstantiation<EnclosingType>),
}

#[derive(Debug, Clone)]
pub enum BaseType<EnclosingType> {
    Type(TypeSource<EnclosingType>),
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
    Vector(Option<CustomTypeModifier>, EnclosingType),
    Array(EnclosingType, ArrayShape),
    ValuePointer(Option<CustomTypeModifier>, Option<EnclosingType>),
    FunctionPointer(signature::ManagedMethod),
}

#[derive(Debug, Clone)]
pub enum MemberType {
    Base(Box<BaseType<MemberType>>),
    TypeGeneric(usize),
}

#[derive(Debug, Clone)]
pub enum MethodType {
    Base(Box<BaseType<MethodType>>),
    TypeGeneric(usize),
    MethodGeneric(usize),
}

#[derive(Debug)]
pub enum LocalVariable {
    TypedReference,
    Variable {
        custom_modifier: Option<CustomTypeModifier>,
        pinned: bool,
        by_ref: bool,
        var_type: MethodType,
    },
}

pub trait Resolver {
    type Error: std::error::Error;
    fn find_type<'a>(&self, name: &str) -> Result<(&'a TypeDefinition<'a>, &'a Resolution<'a>), Self::Error>;
}
