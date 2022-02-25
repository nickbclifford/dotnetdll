use super::{
    attribute::{Attribute, SecurityDeclaration},
    generic::{show_constraints, TypeGeneric},
    members, signature, ResolvedDebug,
};
use crate::binary::signature::{encoded::ArrayShape, kinds::StandAloneCallingConvention};
use crate::convert::TypeKind;
use crate::resolution::*;
use dotnetdll_macros::From;
use std::fmt::{Display, Formatter, Write};

pub use dotnetdll_macros::ctype;

#[derive(Debug, Copy, Clone)]
pub enum Kind {
    Class,
    Interface,
}

#[derive(Debug, Copy, Clone)]
pub enum Accessibility {
    NotPublic,
    Public,
    Nested(super::Accessibility),
}

#[derive(Debug, Copy, Clone)]
pub struct SequentialLayout {
    pub packing_size: usize,
    pub class_size: usize,
}

#[derive(Debug, Copy, Clone)]
pub struct ExplicitLayout {
    pub class_size: usize,
}

#[derive(Debug, Copy, Clone)]
pub enum Layout {
    Automatic,
    Sequential(Option<SequentialLayout>),
    Explicit(Option<ExplicitLayout>),
}

#[derive(Debug, Copy, Clone)]
pub enum StringFormatting {
    ANSI,
    Unicode,
    Automatic,
    Custom(u32),
}

#[derive(Debug, Copy, Clone)]
pub struct MethodOverride {
    pub implementation: members::UserMethod,
    pub declaration: members::UserMethod,
}

#[derive(Debug, Copy, Clone)]
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
    pub const fn default() -> Self {
        Self {
            accessibility: Accessibility::NotPublic,
            layout: Layout::Automatic,
            kind: Kind::Class,
            abstract_type: false,
            sealed: false,
            special_name: false,
            imported: false,
            serializable: false,
            string_formatting: StringFormatting::ANSI,
            before_field_init: true,
            runtime_special_name: false,
        }
    }

    pub(crate) fn from_mask(bitmask: u32, layout: Layout) -> TypeFlags {
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
            before_field_init: check_bitmask!(bitmask, 0x0010_0000),
            runtime_special_name: check_bitmask!(bitmask, 0x800),
        }
    }

    pub fn to_mask(self) -> u32 {
        let mut mask = build_bitmask!(self,
            abstract_type => 0x80,
            sealed => 0x100,
            special_name => 0x400,
            imported => 0x1000,
            serializable => 0x2000,
            before_field_init => 0x0010_0000,
            runtime_special_name => 0x800);
        mask |= match self.accessibility {
            Accessibility::NotPublic => 0x0,
            Accessibility::Public => 0x1,
            Accessibility::Nested(super::Accessibility::Public) => 0x2,
            Accessibility::Nested(super::Accessibility::Private) => 0x3,
            Accessibility::Nested(super::Accessibility::Family) => 0x4,
            Accessibility::Nested(super::Accessibility::Assembly) => 0x5,
            Accessibility::Nested(super::Accessibility::FamilyANDAssembly) => 0x6,
            Accessibility::Nested(super::Accessibility::FamilyORAssembly) => 0x7,
        };
        mask |= match self.layout {
            Layout::Automatic => 0x00,
            Layout::Sequential(_) => 0x08,
            Layout::Explicit(_) => 0x10,
        };
        mask |= match self.kind {
            Kind::Class => 0x00,
            Kind::Interface => 0x20,
        };
        mask |= match self.string_formatting {
            StringFormatting::ANSI => 0x00000,
            StringFormatting::Unicode => 0x10000,
            StringFormatting::Automatic => 0x20000,
            StringFormatting::Custom(val) => 0x30000 | (val & 0x00C0_0000),
        };
        mask
    }
}
impl Default for TypeFlags {
    fn default() -> Self {
        Self::default()
    }
}

#[derive(Debug, Clone)]
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
            self.nested_type_name(res),
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

impl<'a> TypeDefinition<'a> {
    pub const fn new(namespace: Option<&'a str>, name: &'a str) -> Self {
        Self {
            attributes: vec![],
            name,
            namespace,
            fields: vec![],
            properties: vec![],
            methods: vec![],
            events: vec![],
            encloser: None,
            overrides: vec![],
            extends: None,
            implements: vec![],
            generic_parameters: vec![],
            flags: TypeFlags::default(),
            security: None,
        }
    }

    pub fn nested_type_name(&self, res: &Resolution<'a>) -> String {
        match self.encloser {
            Some(enc) => format!("{}/{}", res[enc], self),
            None => self.type_name(),
        }
    }
}

#[derive(Debug, Copy, Clone, From)]
pub enum ResolutionScope {
    Nested(TypeRefIndex),
    ExternalModule(ModuleRefIndex),
    CurrentModule,
    Assembly(AssemblyRefIndex),
    Exported,
}

#[derive(Debug, Clone)]
pub struct ExternalTypeReference<'a> {
    pub attributes: Vec<Attribute<'a>>,
    pub name: &'a str,
    pub namespace: Option<&'a str>,
    pub scope: ResolutionScope,
}

impl<'a> ResolvedDebug for ExternalTypeReference<'a> {
    fn show(&self, res: &Resolution) -> String {
        use ResolutionScope::*;
        match self.scope {
            Nested(enc) => format!("{}/{}", res[enc].show(res), self.name),
            ExternalModule(m) => format!("[module {}]{}", res[m].name, self),
            CurrentModule => self.type_name(),
            Assembly(a) => format!("[{}]{}", res[a].name, self),
            Exported => format!(
                "[{}]{}",
                match res
                    .exported_types
                    .iter()
                    .find(|e| e.name == self.name && e.namespace == self.namespace)
                {
                    Some(e) => match e.implementation {
                        TypeImplementation::Nested(_) => panic!("exported type ref scopes cannot be nested"),
                        TypeImplementation::ModuleFile { file, .. } => res[file].name,
                        TypeImplementation::TypeForwarder(a) => res[a].name,
                    },
                    None => panic!("missing exported type entry for type ref"),
                },
                self
            ),
        }
    }
}

impl<'a> ExternalTypeReference<'a> {
    pub const fn new(namespace: Option<&'a str>, name: &'a str, scope: ResolutionScope) -> Self {
        Self {
            attributes: vec![],
            name,
            namespace,
            scope,
        }
    }
}

#[derive(Debug, Copy, Clone, From)]
pub enum TypeImplementation {
    Nested(ExportedTypeIndex),
    ModuleFile { type_def: TypeIndex, file: FileIndex },
    TypeForwarder(AssemblyRefIndex),
}

#[derive(Debug, Clone)]
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

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, From)]
pub enum UserType {
    Definition(TypeIndex),
    Reference(TypeRefIndex),
}

impl UserType {
    pub fn type_name(&self, r: &Resolution) -> String {
        match self {
            UserType::Definition(idx) => r[*idx].type_name(),
            UserType::Reference(idx) => r[*idx].type_name(),
        }
    }
}

impl ResolvedDebug for UserType {
    fn show(&self, res: &Resolution) -> String {
        match self {
            UserType::Definition(idx) => res[*idx].nested_type_name(res),
            UserType::Reference(idx) => res[*idx].show(res),
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum CustomTypeModifier {
    Optional(UserType),
    Required(UserType),
}
impl ResolvedDebug for CustomTypeModifier {
    fn show(&self, res: &Resolution) -> String {
        use CustomTypeModifier::*;
        match self {
            Optional(t) => format!("<opt {}>", t.show(res)),
            Required(t) => format!("<req {}>", t.show(res)),
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub enum InstantiationKind {
    Class,
    ValueType,
}

// the ECMA standard does not necessarily say anything about what TypeSpecs are allowed as supertypes
// however, looking at the stdlib and assemblies shipped with .NET 5, it appears that only GenericInstClass is used
#[derive(Debug, Clone, PartialEq, Eq, Hash, From)]
pub enum TypeSource<EnclosingType> {
    User(#[nested(TypeIndex, TypeRefIndex)] UserType),
    Generic {
        base_kind: InstantiationKind,
        base: UserType,
        parameters: Vec<EnclosingType>,
    },
}
impl<T: ResolvedDebug> ResolvedDebug for TypeSource<T> {
    fn show(&self, res: &Resolution) -> String {
        use TypeSource::*;
        match self {
            User(u) => u.show(res),
            Generic { base, parameters, .. } => format!(
                "{}<{}>",
                base.show(res),
                parameters.iter().map(|p| p.show(res)).collect::<Vec<_>>().join(", ")
            ),
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum ValueKind {
    Class,
    ValueType,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum BaseType<EnclosingType> {
    Type {
        value_kind: ValueKind,
        source: TypeSource<EnclosingType>,
    },
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
            Type { value_kind: value_type, source } => {
                format!("{}{}", if *value_type == ValueKind::ValueType { "valuetype " } else { "" }, source.show(res))
            }
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

impl<T> BaseType<T> {
    pub const fn vector(inner: T) -> Self {
        BaseType::Vector(vec![], inner)
    }

    pub const VOID_PTR: Self = BaseType::ValuePointer(vec![], None);

    pub const fn pointer(pointee: T) -> Self {
        BaseType::ValuePointer(vec![], Some(pointee))
    }
}

macro_rules! impl_from {
    ($t:ty) => {
        impl From<BaseType<$t>> for $t {
            fn from(b: BaseType<$t>) -> Self {
                TypeKind::from_base(b)
            }
        }
    };
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum MemberType {
    // NOTE: lots of heap allocation taking place because of how common this type is
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
impl_from!(MemberType);

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum MethodType {
    // ditto
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
impl_from!(MethodType);

impl From<MemberType> for MethodType {
    fn from(m: MemberType) -> Self {
        // SAFETY: since both types are tagged repr(u8), they have a defined layout
        // since MethodType is a superset of MemberType, these layouts intersect
        // thus, every MemberType is a valid MethodType, and this transmutation is valid
        unsafe { std::mem::transmute(m) }
    }
}

#[derive(Debug, Clone)]
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
impl LocalVariable {
    pub const fn new(var_type: MethodType) -> Self {
        Self::Variable {
            custom_modifiers: vec![],
            pinned: false,
            by_ref: false,
            var_type
        }
    }
}

pub trait Resolver<'a> {
    type Error: std::error::Error;
    fn find_type(&self, name: &str) -> Result<(&TypeDefinition<'a>, &Resolution<'a>), Self::Error>;
}
