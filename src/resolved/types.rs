use std::fmt::{Display, Formatter, Write};

use crate::binary::signature::{encoded::ArrayShape, kinds::StandAloneCallingConvention};
use crate::resolution::*;

use super::{
    attribute::{Attribute, SecurityDeclaration},
    generic::{show_constraints, TypeGeneric},
    members, signature, ResolvedDebug,
};

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
pub struct MethodOverride {
    pub implementation: members::UserMethod,
    pub declaration: members::UserMethod,
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
                0x4 => Nested(super::Accessibility::Family),
                0x5 => Nested(super::Accessibility::Assembly),
                0x6 => Nested(super::Accessibility::FamilyANDAssembly),
                0x7 => Nested(super::Accessibility::FamilyORAssembly),
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
                0x30000 => StringFormatting::Custom(bitmask & 0x00C0_0000),
                _ => unreachable!(),
            },
            before_field_init: check_bitmask!(bitmask, 0x0100_0000),
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
    pub encloser: Option<TypeIndex>,
    pub overrides: Vec<MethodOverride>,
    pub extends: Option<TypeSource<MemberType>>,
    pub implements: Vec<(Vec<Attribute<'a>>, TypeSource<MemberType>)>,
    pub generic_parameters: Vec<TypeGeneric<'a>>,
    pub flags: TypeFlags,
    pub security: Option<SecurityDeclaration<'a>>,
}
impl ResolvedDebug for TypeDefinition<'_> {
    fn show(&self, res: &Resolution) -> String {
        let mut buf = String::new();

        match &self.flags.accessibility {
            Accessibility::NotPublic => {}
            Accessibility::Public => buf.push_str("public "),
            Accessibility::Nested(a) => write!(buf, "{} ", a).unwrap(),
        }

        if let Some(idx) = &self.encloser {
            write!(buf, "[{}] ", res[*idx]).unwrap();
        }

        let kind = match &self.flags.kind {
            Kind::Class => match &self.extends {
                Some(TypeSource::User(u)) => match u.type_name(res).as_str() {
                    "System.Enum" => "enum",
                    "System.ValueType" => "struct",
                    _ => "class",
                },
                _ => "class",
            },
            Kind::Interface => "interface",
        };

        if self.flags.abstract_type && kind != "interface" {
            buf.push_str("abstract ");
        }

        write!(
            buf,
            "{} {}{}",
            kind,
            self.type_name(),
            self.generic_parameters.show(res)
        )
        .unwrap();

        if let Some(ext) = &self.extends {
            let supertype = ext.show(res);
            if kind == "class" && supertype != "System.Object" {
                write!(buf, " extends {}", supertype).unwrap();
            }
        }

        if !self.implements.is_empty() {
            write!(
                buf,
                " implements {}",
                self.implements
                    .iter()
                    .map(|(_, t)| t.show(res))
                    .collect::<Vec<_>>()
                    .join(", ")
            )
            .unwrap();
        }

        if let Some(s) = show_constraints(&self.generic_parameters, res) {
            write!(buf, " {}", s).unwrap();
        }

        buf
    }
}

#[derive(Debug)]
pub enum ResolutionScope {
    Nested(usize),
    ExternalModule(ModuleRefIndex),
    CurrentModule,
    Assembly(AssemblyRefIndex),
    Exported(ExportedTypeIndex),
}

#[derive(Debug)]
pub struct ExternalTypeReference<'a> {
    pub attributes: Vec<Attribute<'a>>,
    pub name: &'a str,
    pub namespace: Option<&'a str>,
    pub scope: ResolutionScope,
}

#[derive(Debug)]
pub enum TypeImplementation {
    Nested(ExportedTypeIndex),
    ModuleFile {
        type_def: TypeIndex,
        file: FileIndex,
    },
    TypeForwarder(AssemblyRefIndex),
}

#[derive(Debug)]
pub struct ExportedType<'a> {
    pub attributes: Vec<Attribute<'a>>,
    pub flags: TypeFlags,
    pub name: &'a str,
    pub namespace: Option<&'a str>,
    pub implementation: TypeImplementation,
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

        impl Display for $i {
            fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
                write!(f, "{}", self.type_name())
            }
        }
    };
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
impl ResolvedDebug for CustomTypeModifier {
    fn show(&self, res: &Resolution) -> String {
        use CustomTypeModifier::*;
        match self {
            Optional(t) => format!("[opt {}]", t.type_name(res)),
            Required(t) => format!("[req {}]", t.type_name(res)),
        }
    }
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
impl<T: ResolvedDebug> ResolvedDebug for TypeSource<T> {
    fn show(&self, res: &Resolution) -> String {
        use TypeSource::*;
        match self {
            User(u) => u.type_name(res),
            Generic(g) => format!(
                "{}<{}>",
                g.base.type_name(res),
                g.parameters
                    .iter()
                    .map(|p| p.show(res))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        }
    }
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
    Vector(Vec<CustomTypeModifier>, EnclosingType),
    Array(EnclosingType, ArrayShape),
    ValuePointer(Vec<CustomTypeModifier>, Option<EnclosingType>),
    FunctionPointer(signature::MaybeUnmanagedMethod),
}
impl<T: ResolvedDebug> ResolvedDebug for BaseType<T> {
    fn show(&self, res: &Resolution) -> String {
        use BaseType::*;
        use StandAloneCallingConvention::*;
        match self {
            Type(t) => t.show(res),
            Boolean => "bool".to_string(),
            Char => "char".to_string(),
            Int8 => "sbyte".to_string(),
            UInt8 => "byte".to_string(),
            Int16 => "short".to_string(),
            UInt16 => "ushort".to_string(),
            Int32 => "int".to_string(),
            UInt32 => "uint".to_string(),
            Int64 => "long".to_string(),
            UInt64 => "ulong".to_string(),
            Float32 => "float".to_string(),
            Float64 => "double".to_string(),
            IntPtr => "nint".to_string(),
            UIntPtr => "nuint".to_string(),
            Object => "object".to_string(),
            String => "string".to_string(),
            Vector(_, t) => format!("{}[]", t.show(res)),
            Array(t, shape) => format!("{}{}", t.show(res), "[]".repeat(shape.rank)), // can't be bothered to do explicit dimensions atm
            ValuePointer(_, opt) => match opt {
                Some(t) => format!("{}*", t.show(res)),
                None => "void*".to_string(),
            },
            FunctionPointer(sig) => format!(
                "delegate*{}<{}>",
                match sig.calling_convention {
                    DefaultManaged => "".to_string(),
                    DefaultUnmanaged => " unmanaged".to_string(),
                    other => format!(" unmanaged[{:?}]", other),
                },
                sig.parameters
                    .iter()
                    .map(|p| p.1.show(res))
                    .chain(std::iter::once(match &sig.return_type.1 {
                        None => "void".to_string(),
                        Some(t) => t.show(res),
                    }))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        }
    }
}

#[derive(Debug, Clone)]
pub enum MemberType {
    Base(Box<BaseType<MemberType>>),
    TypeGeneric(usize),
}
impl ResolvedDebug for MemberType {
    fn show(&self, res: &Resolution) -> String {
        use MemberType::*;
        match self {
            Base(b) => b.show(res),
            TypeGeneric(i) => format!("T{}", i),
        }
    }
}

#[derive(Debug, Clone)]
pub enum MethodType {
    Base(Box<BaseType<MethodType>>),
    TypeGeneric(usize),
    MethodGeneric(usize),
}
impl ResolvedDebug for MethodType {
    fn show(&self, res: &Resolution) -> String {
        use MethodType::*;
        match self {
            Base(b) => b.show(res),
            TypeGeneric(i) => format!("T{}", i),
            MethodGeneric(i) => format!("M{}", i),
        }
    }
}

#[derive(Debug)]
pub enum LocalVariable {
    TypedReference,
    Variable {
        custom_modifiers: Vec<CustomTypeModifier>,
        pinned: bool,
        by_ref: bool,
        var_type: MethodType,
    },
}
impl ResolvedDebug for LocalVariable {
    fn show(&self, res: &Resolution) -> String {
        use LocalVariable::*;

        match self {
            TypedReference => "System.TypedReference".to_string(),
            Variable {
                custom_modifiers,
                pinned,
                by_ref,
                var_type,
            } => {
                let mut buf = String::new();

                for m in custom_modifiers {
                    write!(buf, "{} ", m.show(res)).unwrap();
                }

                if *pinned {
                    buf.push_str("fixed ");
                }

                if *by_ref {
                    buf.push_str("ref ");
                }

                write!(buf, "{}", var_type.show(res)).unwrap();

                buf
            }
        }
    }
}

pub trait Resolver<'a> {
    type Error: std::error::Error;
    fn find_type(&self, name: &str) -> Result<(&TypeDefinition<'a>, &Resolution<'a>), Self::Error>;
}
