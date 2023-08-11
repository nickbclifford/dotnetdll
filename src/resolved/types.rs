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
    /// Runtime security metadata associated with the type.
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


/// A reference to a type that is defined externally to the current DLL or module.
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
/// The `EnclosingType` type parameter represents the types allowed in the list of parameters instantiating a generic type.
/// See [`BaseType`]'s documentation for more information.
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

/// A sum type containing all fundamental types of .NET, including user type references, primitive value types, primitive reference types, and unmanaged pointers.
///
/// ## Primitives versus `System.*` References
/// When encoding type signature information, primitive types should be represented with their corresponding primitive variants
/// instead of with a reference to their location in the `System` namespace (ECMA-335, II.23.2.16, page 267).
///
/// For example, when encoding a 32-bit signed integer, one should always use the `BaseType::Int32` variant
/// and not a `BaseType::Type` with an [`ExternalTypeReference`] to `System.Int32`.
///
/// A future version of dotnetdll may eventually automatically check for such references and either automatically convert them to the correct format
/// **or** throw errors when they are encountered.
///
/// ## Generics and `EnclosingType`
/// You'll notice that `BaseType` not only does not include a variant for quantified generic type variables,
/// but also is defined with its own type parameter `EnclosingType`.
/// These are for the same reason: in the interest of making invalid types unrepresentable,
/// dotnetdll puts generic type variables into separate [`MemberType`] and [`MethodType`]
/// enums that wrap `BaseType` by instantiating *themselves* as the `EnclosingType`.
///
/// At the metadata level, generic type variables from a generic type and those from a generic method are represented differently,
/// and this trick of composing `BaseType` allows dotnetdll to prevent method type variables from being used anywhere other than in
/// a method's signature.
///
/// ### Examples
/// Here, the variables `T0`, `T1`, etc. represent type variables from a generic type declaration (i.e. `public class MyType<T0, T1, ...>`),
/// whereas `M0`, `M1`, etc. are those from a generic method declaration (i.e. `public void MyMethod<M0, M1, ...>()`).
///
/// A [`Field`](members::Field)'s [`return_type`](members::Field::return_type) is a [`MemberType`],
/// which wraps a `BaseType<MemberType>` with an additional variant for type variables from a generic type.
/// This means a field's type could be `T0`, `T1[]`, or `T2*`, but not `M0`, because there is no quantification from a generic method to introduce `M0`.
///
/// A [`Method`](members::Method)'s [`signature`](members::Method::signature) is a [`signature::ManagedMethod`], which represents
/// parameters and return types with [`MethodType`]s. `T0`, `T1[]`, etc. are acceptable types here, but because this is in a method context,
/// [`MethodType`] has an additional variant for method generic type variables that means `M0`, `M1[]`, etc. are acceptable as well.
///
/// ## Which type do I use?
/// - If you are representing types in a method signature (parameters or return types), use [`MethodType`].
/// - If you are representing types in any other position, use [`MemberType`].
/// - If you are writing something that has to act generically over both [`MemberType`] and [`MethodType`],
///   use `BaseType<T>` with appropriate trait bounds on `T`.
///
/// ## Conversions
/// `BaseType` defines free [`From`]/[`Into`] trait conversions with [`TypeSource`], [`MemberType`], and [`MethodType`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum BaseType<EnclosingType> {
    /// A type definition, type reference, or generic instantiation.
    Type {
        // TODO: explain ValueKind and when it can be omitted
        value_kind: Option<ValueKind>,
        source: TypeSource<EnclosingType>,
    },
    /// The primitive `System.Boolean` type, which is either `true` or `false`. Equivalent to C#'s `bool` type.
    Boolean,
    /// The primitive `System.Char` type, which is a UTF-16 code unit. Equivalent to C#'s `char` type.
    Char,
    /// The primitive `System.Int8` type, which is an 8-bit signed integer. Equivalent to C#'s `sbyte` type.
    Int8,
    /// The primitive `System.UInt8` type, which is an 8-bit unsigned integer. Equivalent to C#'s `byte` type.
    UInt8,
    /// The primitive `System.Int16` type, which is a 16-bit signed integer. Equivalent to C#'s `short` type.
    Int16,
    /// The primitive `System.UInt16` type, which is a 16-bit unsigned integer. Equivalent to C#'s `ushort` type.
    UInt16,
    /// The primitive `System.Int32` type, which is a 32-bit signed integer. Equivalent to C#'s `int` type.
    Int32,
    /// The primitive `System.UInt32` type, which is a 32-bit unsigned integer. Equivalent to C#'s `uint` type.
    UInt32,
    /// The primitive `System.Int64` type, which is a 64-bit signed integer. Equivalent to C#'s `long` type.
    Int64,
    /// The primitive `System.UInt64` type, which is a 64-bit unsigned integer. Equivalent to C#'s `ulong` type.
    UInt64,
    /// The primitive `System.Single` type, which is a 32-bit single-precision IEEE 754 floating point number. Equivalent to C#'s `float` type.
    Float32,
    /// The primitive `System.Double` type, which is a 64-bit double-precision IEEE 754 floating point number.  Equivalent to C#'s `double` type.
    Float64,
    /// The primitive `System.IntPtr` type, which is a signed integer with the platform's native integer size. Equivalent to C#'s `nint` type.
    IntPtr,
    /// The primitive `System.UIntPtr` type, which is an unsigned integer with the platform's native integer size. Equivalent to C#'s `nuint` type.
    UIntPtr,
    /// The primitive `System.Object` type, which is the base type of all reference types in .NET. Equivalent to C#'s `object` type.
    Object,
    /// The primitive `System.String` type, which is a sequence of UTF-16 characters. Equivalent to C#'s `string` type.
    String,
    /// A zero-indexed single dimensional array of unspecified size. Equivalent to C#'s `T[]` type.
    ///
    /// May contain [`CustomTypeModifier`]s that change the type of the element.
    ///
    /// See [`BaseType::vector`] for a convenience constructor for types with no modifiers.
    Vector(Vec<CustomTypeModifier>, EnclosingType),
    /// A potentially multi-dimensional array with defined lower bounds and potentially fixed sizes, specified by [`ArrayShape`].
    /// Equivalent to C#'s `T[,]` and `T[M, N, ...]` types.
    ///
    /// See ECMA-335, II.23.2.13 (page 265) for more information.
    Array(EnclosingType, ArrayShape),
    /// A pointer, either to a typed value or to `void`. Equivalent to C#'s `void*` and `T*` types.
    ///
    /// May contain [`CustomTypeModifier`]s that change the type of the pointee.
    ///
    /// See [`BaseType::VOID_PTR`] and [`BaseType::pointer`] for convenience constructors for types with no modifiers..
    ValuePointer(Vec<CustomTypeModifier>, Option<EnclosingType>),
    /// A pointer to a function, which may be a .NET managed method or an unmanaged native function.
    /// Equivalent to C#'s `delegate*<T..., R>` type.
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
/// A sum type that wraps [`BaseType`] and includes type variables quantified by a type's generic parameters declaration.
///
/// See [`BaseType`] for a detailed explanation of this type's structure and its relationship to [`BaseType`] and [`MethodType`].
///
/// [`MemberType`] defines a free [`From`]/[`Into`] conversion with [`MethodType`].
pub enum MemberType {
    // NOTE: lots of heap allocation taking place because of how common this type is
    Base(Box<BaseType<MemberType>>),
    /// Represents the type variable present at the specified 0-based index in the type's generic parameter list.
    ///
    /// For example, inside a type declaration `public class ExampleType<T, U, V>`, `U` would be represented by `TypeGeneric(1)`.
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
/// A sum type that wraps [`BaseType`] and includes type variables quantified by either a type's or a method's generic parameters declaration.
///
/// See [`BaseType`] for a detailed explanation of this type's structure and its relationship to [`BaseType`] and [`MemberType`].
///
/// [`MethodType`] defines a free [`From`]/[`Into`] conversion with [`MemberType`].
pub enum MethodType {
    // ditto
    Base(Box<BaseType<MethodType>>),
    /// Represents the type variable present at the specified 0-based index in the type's generic parameter list.
    ///
    /// For example, inside a type declaration `public class ExampleType<T, U, V>`, `U` would be represented by `TypeGeneric(1)`.
    TypeGeneric(usize),
    /// Represents the type variable present at the specified 0-based index in the method's generic parameter list.
    ///
    /// For example, inside a generic method `public V ExampleMethod<T, U, V>()`, `V` would be represented by `MethodGeneric(2)`.
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
