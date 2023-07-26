use super::{
    attribute::{Attribute, SecurityDeclaration},
    generic::{show_constraints, Type},
    members, signature, ResolvedDebug,
};
use crate::binary::signature::{encoded::ArrayShape, kinds::StandAloneCallingConvention};
use crate::convert::TypeKind;
use crate::resolution::*;
use dotnetdll_macros::From;
use std::borrow::Cow;
use std::fmt::{Display, Formatter, Write};
use thiserror::Error;

pub use dotnetdll_macros::{ctype, type_name, type_ref};

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
impl Default for TypeFlags {
    fn default() -> Self {
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
            before_field_init: false,
            runtime_special_name: false,
        }
    }
}

impl TypeFlags {
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

/// A .NET type definition, including all the members that type declares.
///
/// A `TypeDefinition` instance represents the complete declaration of a type defined inside its owning [`Resolution`].
/// This includes members, object-oriented characteristics like inheritance and accessibility, generic type information, and all other metadata declared on a type.
#[derive(Debug, Clone)]
pub struct TypeDefinition<'a> {
    /// All attributes present on the type's declaration.
    pub attributes: Vec<Attribute<'a>>,
    /// Name of the type.
    pub name: Cow<'a, str>,
    /// Namespace of the type, if it resides within one.
    pub namespace: Option<Cow<'a, str>>,
    /// Fields that the type declares.
    pub fields: Vec<members::Field<'a>>,
    /// Properties that the type declares.
    pub properties: Vec<members::Property<'a>>,
    /// Methods that the type declares.
    pub methods: Vec<members::Method<'a>>,
    /// Events that the type declares.
    pub events: Vec<members::Event<'a>>,
    /// The enclosing type, if this type is nested inside another.
    pub encloser: Option<TypeIndex>,
    /// Method interface implementation overrides that the type declares.
    pub overrides: Vec<MethodOverride>,
    /// The type that this type extends, if any.
    ///
    /// Note that all types extend another except for `System.Object` itself.
    /// This field is an `Option` so that types such as `System.Object` are still representable.
    pub extends: Option<TypeSource<MemberType>>,
    /// Interfaces that the type implements, including any attributes present on the interface implementation metadata.
    pub implements: Vec<(Vec<Attribute<'a>>, TypeSource<MemberType>)>,
    /// Generic type parameters, if the type declares any.
    pub generic_parameters: Vec<Type<'a>>,
    /// Additional details and flags regarding the type, including accessibility and inheritance modifiers.
    pub flags: TypeFlags,
    /// Security metadata associated with the type.
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
    pub fn new(namespace: Option<Cow<'a, str>>, name: impl Into<Cow<'a, str>>) -> Self {
        Self {
            attributes: vec![],
            name: name.into(),
            namespace: namespace.map(Into::into),
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

    pub fn add_implementation(&mut self, interface_type: impl Into<TypeSource<MemberType>>) {
        self.implements.push((vec![], interface_type.into()));
    }

    pub fn set_extends(&mut self, parent_type: impl Into<TypeSource<MemberType>>) {
        self.extends = Some(parent_type.into());
    }
}

/// Outlines the possible locations where an externally defined type could be, thus specifying the scope of reference resolution for an [`ExternalTypeReference`].
#[derive(Debug, Copy, Clone, PartialEq, Eq, From)]
pub enum ResolutionScope {
    /// Indicates that the type is nested within another type.
    Nested(TypeRefIndex),
    /// Indicates that the type is located in an external module within the same assembly as this [`ExternalTypeReference`]'s owning module.
    ExternalModule(ModuleRefIndex),
    /// Indicates that the type is located in the current module.
    // TODO: explain how this is different from an index to a TypeDef
    CurrentModule,
    /// Indicates that the type is located in an external assembly.
    Assembly(AssemblyRefIndex),
    /// Indicates that the type is an exported type. See [`ExportedType`] for details.
    Exported,
}


/// A reference to type that is defined externally to the current DLL or module.
///
/// This could point to a type defined in another module in the same assembly, a different DLL altogether, or a type that is nested within another type.
/// The external location is specified by the `scope` member.
#[derive(Debug, Clone)]
pub struct ExternalTypeReference<'a> {
    /// All attributes presents on this type reference's metadata record.
    pub attributes: Vec<Attribute<'a>>,
    /// Name of the type as defined in the external scope.
    pub name: Cow<'a, str>,
    /// Namespace of the type, if it resides within one.
    pub namespace: Option<Cow<'a, str>>,
    /// Reference resolution scope, indicating where the type is defined.
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
                        TypeImplementation::ModuleFile { file, .. } => &res[file].name,
                        TypeImplementation::TypeForwarder(a) => &res[a].name,
                    },
                    None => panic!("missing exported type entry for type ref"),
                },
                self
            ),
        }
    }
}

impl<'a> ExternalTypeReference<'a> {
    pub fn new(namespace: Option<Cow<'a, str>>, name: impl Into<Cow<'a, str>>, scope: ResolutionScope) -> Self {
        Self {
            attributes: vec![],
            name: name.into(),
            namespace,
            scope,
        }
    }
}

/// Specifies where the implementation (i.e. [`TypeDefinition`]) of an [`ExportedType`] is.
#[derive(Debug, Copy, Clone, From)]
pub enum TypeImplementation {
    /// Indicates that this type is nested within another type exported by this assembly.
    Nested(ExportedTypeIndex),
    /// Indicates that this type is present within another module of this assembly.
    ///
    /// Note that the standard specifies that the `type_def` field is a *hint only*, and that resolution should be ultimately determined by
    /// the [`ExportedType`] declaration's `name` and `namespace`. See ECMA-335, II.22.14 (page 222) for more information.
    ModuleFile {
        /// The module that the type's implementation resides in.
        file: FileIndex,
        /// An index into the external module's [`Resolution::type_definitions`] table.
        type_def: TypeIndex,
    },
    /// Indicates that this type was originally defined within the current assembly, but has since moved to an external assembly.
    TypeForwarder(AssemblyRefIndex),
}

/// A type exported by and made available in this assembly, but not present in the module that defines the assembly.
///
/// Note that this is different from simply a `public` type. An `ExportedType` declaration means that the type with the given name and namespace
/// is made available by this assembly; i.e., external modules can reference this type by importing this assembly; however, the *implementation*
/// resides in a module other than the assembly's main module.
///
/// For more information, see the following sections of the standard:
/// - `ilasm` type export declarations: ECMA-335, II.6.7 (page 120)
/// - `ExportedType` metadata records: ECMA-335, II.22.14 (page 222)
#[derive(Debug, Clone)]
pub struct ExportedType<'a> {
    /// All attributes present on the type export declaration.
    pub attributes: Vec<Attribute<'a>>,
    /// Additional details and flags regarding the type, including accessibility and inheritance modifiers.
    pub flags: TypeFlags,
    /// Name of the type.
    pub name: Cow<'a, str>,
    /// Namespace of the type, if it resides within one.
    pub namespace: Option<Cow<'a, str>>,
    /// The location of the type's complete declaration and implementation.
    pub implementation: TypeImplementation,
}

macro_rules! type_name_impl {
    ($i:ty) => {
        impl $i {
            pub fn type_name(&self) -> String {
                match self.namespace.as_ref() {
                    Some(ns) => format!("{}.{}", ns, &self.name),
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

/// Sum type that combines a [`TypeIndex`] and [`TypeRefIndex`].
///
/// This type defines free [`From`]/[`Into`] trait conversions with [`TypeIndex`] and [`TypeRefIndex`].
///
/// Semantically, a `UserType` is either a type definition or a type reference; that is, it does not have any generic parameters and it is not a primitive runtime type.
/// It is named because either of these cases represent a type defined by a *user* and not by the runtime itself.
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

/// A [`UserType`] that can be attached to any other type to add additional information to a type.
/// A type with a `CustomTypeModifier` is considered *not equal* to the same type without a modifier.
///
/// The distinction between "optional" and "required" modifiers refers to how compilers and metadata tools treat them:
/// - An optional type modifier can be freely ignored when encountered by a compiler.
/// - A required type modifier should be treated specially by a compiler, as it indicates that the modified type has special semantics that cannot be ignored.
/// See ECMA-335, II.7.1.1 (page 123) for more information.
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

/// Specifies whether the user-defined type being referenced is a class or a value type. Used in the [`BaseType::Type`] variant.
///
/// This is analogous to the `class` and `valuetype` keywords in ILAsm type syntax. See ECMA-335, II.7.1 (page 122) for more information.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum ValueKind {
    Class,
    ValueType,
}

// the ECMA standard does not necessarily say anything about what TypeSpecs are allowed as supertypes
// however, looking at the stdlib and assemblies shipped with .NET 5, it appears that only GenericInstClass is used
/// A sum type representing either a plain [`UserType`] reference or a generic instantiation of a [`UserType`].
///
/// This type defines free [`From`]/[`Into`] trait conversions with [`TypeIndex`] and [`TypeRefIndex`].
///
/// Note that a bare reference is distinct from generic instantiation with zero parameters.
/// The two kinds of type reference are represented differently in metadata (ECMA-335, II.23.2.13, page 265), thus they are represented differently here.
/// When constructing a `TypeSource`, keep this in mind.
#[derive(Debug, Clone, PartialEq, Eq, Hash, From)]
pub enum TypeSource<EnclosingType> {
    User(#[nested(TypeIndex, TypeRefIndex)] UserType),
    Generic {
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

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum BaseType<EnclosingType> {
    Type {
        value_kind: Option<ValueKind>,
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
            Type {
                value_kind: value_type,
                source,
            } => {
                format!(
                    "{}{}",
                    if matches!(value_type, Some(ValueKind::ValueType)) {
                        "valuetype "
                    } else {
                        ""
                    },
                    source.show(res)
                )
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
                    DefaultManaged => std::string::String::new(),
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
impl<T> From<TypeSource<T>> for BaseType<T> {
    fn from(source: TypeSource<T>) -> Self {
        BaseType::Type {
            value_kind: None,
            source,
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

    pub fn class(source: impl Into<TypeSource<T>>) -> Self {
        BaseType::Type {
            value_kind: Some(ValueKind::Class),
            source: source.into(),
        }
    }

    pub fn valuetype(source: impl Into<TypeSource<T>>) -> Self {
        BaseType::Type {
            value_kind: Some(ValueKind::ValueType),
            source: source.into(),
        }
    }
}

macro_rules! impl_typekind {
    ($t:ty) => {
        impl<T: Into<BaseType<$t>>> From<T> for $t {
            fn from(t: T) -> Self {
                TypeKind::from_base(t.into())
            }
        }
        impl $t {
            pub fn as_base(&self) -> Option<&BaseType<$t>> {
                TypeKind::as_base(self)
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
impl_typekind!(MemberType);

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
impl_typekind!(MethodType);

impl From<MemberType> for MethodType {
    fn from(m: MemberType) -> Self {
        // SAFETY: since both types are tagged repr(u8), they have a defined layout
        // since MethodType is a superset of MemberType, these layouts intersect
        // thus, every MemberType is a valid MethodType, and this transmutation is valid
        // TODO: does this need a ManuallyDrop?
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
            var_type,
        }
    }
}

pub trait Resolver<'a> {
    type Error: std::error::Error;
    fn find_type(&self, name: &str) -> Result<(&TypeDefinition<'a>, &Resolution<'a>), Self::Error>;
}

#[derive(Debug, Error)]
#[error("AlwaysFailsResolver always fails (asked to find {0:?})")]
pub struct AlwaysFails(String);

#[derive(Debug)]
pub struct AlwaysFailsResolver;
impl<'a> Resolver<'a> for AlwaysFailsResolver {
    type Error = AlwaysFails;
    fn find_type(&self, name: &str) -> Result<(&TypeDefinition<'a>, &Resolution<'a>), Self::Error> {
        Err(AlwaysFails(name.to_string()))
    }
}
