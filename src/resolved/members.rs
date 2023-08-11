use super::{
    attribute::{Attribute, SecurityDeclaration},
    body,
    generic::{self, show_constraints},
    signature,
    types::{CustomTypeModifier, MemberType, MethodType},
    ResolvedDebug,
};
use crate::resolution::*;
use dotnetdll_macros::From;
use std::borrow::Cow;
use std::fmt::{Display, Formatter, Write};

pub use crate::binary::signature::{encoded::NativeIntrinsic, kinds::MarshalSpec};
pub use dotnetdll_macros::{field_ref, method_ref};

macro_rules! name_display {
    ($i:ty) => {
        impl Display for $i {
            fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
                write!(f, "{}", self.name)
            }
        }
    };
}

#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, From)]
pub enum Accessibility {
    CompilerControlled,
    Access(super::Accessibility),
}
impl Display for Accessibility {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        use Accessibility::*;
        match self {
            CompilerControlled => write!(f, "[compiler controlled]"),
            Access(a) => write!(f, "{}", a),
        }
    }
}
impl Accessibility {
    pub fn to_mask(self) -> u16 {
        match self {
            Accessibility::CompilerControlled => 0x0,
            Accessibility::Access(super::Accessibility::Private) => 0x1,
            Accessibility::Access(super::Accessibility::FamilyANDAssembly) => 0x2,
            Accessibility::Access(super::Accessibility::Assembly) => 0x3,
            Accessibility::Access(super::Accessibility::Family) => 0x4,
            Accessibility::Access(super::Accessibility::FamilyORAssembly) => 0x5,
            Accessibility::Access(super::Accessibility::Public) => 0x6,
        }
    }
}

/// A field definition, owned by a [`TypeDefinition`](super::types::TypeDefinition)'s [`fields`](super::types::TypeDefinition::fields) collection.
#[derive(Debug, Clone)]
pub struct Field<'a> {
    /// All attributes present on the field's declaration.
    pub attributes: Vec<Attribute<'a>>,
    /// Name of the field.
    pub name: Cow<'a, str>,
    /// Custom type modifiers associated with the field's type.
    pub type_modifiers: Vec<CustomTypeModifier>,
    /// Indicates if the field stores a reference to its contents.
    /// See the [C# documentation on `ref` fields](https://learn.microsoft.com/en-us/dotnet/csharp/language-reference/builtin-types/ref-struct#ref-fields)
    /// for details.
    pub by_ref: bool,
    /// Type of the field.
    pub return_type: MemberType,
    /// Visibility scope of the field.
    pub accessibility: Accessibility,
    /// Specifies if the field is a static member of its owning type.
    pub static_member: bool,
    /// Indicates if the field is read-only after initialization.
    pub init_only: bool,
    /// Specifies if the field is a compile-time constant.
    pub literal: bool,
    /// Default constant value of the field, if any.
    pub default: Option<Constant>,
    /// Indicates if the field should be excluded when the type is serialized.
    pub not_serialized: bool,
    /// Specifies if the field is named with special meaning for a compiler.
    // TODO: examples
    pub special_name: bool,
    /// If this field is a P/Invoke binding, specifies the import information.
    pub pinvoke: Option<PInvoke<'a>>,
    /// Specifies if the field is named with special meaning for the runtime.
    // TODO: examples (enum value__, ...)
    pub runtime_special_name: bool,
    /// Specifies the explicit byte offset of this field within its owning type, if provided.
    pub offset: Option<usize>,
    /// Specifies the custom marshaling behavior of the field, if defined.
    pub marshal: Option<MarshalSpec>,
    /// If the field was declared with data directly embedded in the DLL file, specifies the field's initial byte value.
    pub initial_value: Option<Cow<'a, [u8]>>,
}

name_display!(Field<'_>);
impl ResolvedDebug for Field<'_> {
    fn show(&self, res: &Resolution) -> String {
        let mut buf = format!("{} ", self.accessibility);

        if self.static_member {
            buf.push_str("static ");
        }

        write!(buf, "{} {}", self.return_type.show(res), self.name).unwrap();

        if let Some(c) = &self.default {
            write!(buf, " = {:?}", c).unwrap();
        }

        buf
    }
}
impl<'a> Field<'a> {
    pub fn new(
        static_member: bool,
        access: super::Accessibility,
        name: impl Into<Cow<'a, str>>,
        return_type: MemberType,
    ) -> Self {
        Self {
            attributes: vec![],
            name: name.into(),
            type_modifiers: vec![],
            by_ref: false,
            return_type,
            accessibility: Accessibility::Access(access),
            static_member,
            init_only: false,
            literal: false,
            default: None,
            not_serialized: false,
            special_name: false,
            pinvoke: None,
            runtime_special_name: false,
            offset: None,
            marshal: None,
            initial_value: None,
        }
    }

    pub fn instance(access: super::Accessibility, name: impl Into<Cow<'a, str>>, return_type: MemberType) -> Self {
        Self::new(false, access, name, return_type)
    }

    pub fn static_member(access: super::Accessibility, name: impl Into<Cow<'a, str>>, return_type: MemberType) -> Self {
        Self::new(true, access, name, return_type)
    }
}

/// Outlines the possible locations where an externally defined field could be, thus specifying the parent type for an [`ExternalFieldReference`].
#[derive(Debug, Clone, From, Eq, PartialEq)]
pub enum FieldReferenceParent {
    /// Indicates that the field is located on an external type, including primitive types.
    Type(MethodType),
    /// Indicates that the field is a global field on an external module.
    // TODO: explain module globals
    Module(ModuleRefIndex),
}

/// A reference to a field whose owning type is defined externally to the current DLL or module.
#[derive(Debug, Clone)]
pub struct ExternalFieldReference<'a> {
    /// All attributes presents on this field reference's metadata record.
    pub attributes: Vec<Attribute<'a>>,
    /// Parent location of the field reference, which could be a type or a module.
    pub parent: FieldReferenceParent,
    /// Name of the field.
    pub name: Cow<'a, str>,
    /// Custom type modifiers associated with the field's type.
    pub custom_modifiers: Vec<CustomTypeModifier>,
    /// Type of the field.
    pub field_type: MemberType,
}

name_display!(ExternalFieldReference<'_>);
impl<'a> ExternalFieldReference<'a> {
    pub const fn new(parent: FieldReferenceParent, field_type: MemberType, name: Cow<'a, str>) -> Self {
        Self {
            attributes: vec![],
            parent,
            name,
            custom_modifiers: vec![],
            field_type,
        }
    }
}

#[derive(Debug, Copy, Clone, From, Eq, PartialEq)]
pub enum FieldSource {
    Definition(FieldIndex),
    Reference(FieldRefIndex),
}
impl ResolvedDebug for FieldSource {
    fn show(&self, res: &Resolution) -> String {
        use FieldSource::*;

        match self {
            Definition(i) => {
                format!("{}.{}", res[i.parent_type].nested_type_name(res), res[*i].name)
            }
            Reference(i) => {
                use FieldReferenceParent::*;

                let f = &res[*i];
                format!(
                    "{}.{}",
                    match &f.parent {
                        Type(t) => t.show(res),
                        Module(m) => res[*m].name.to_string(),
                    },
                    f.name
                )
            }
        }
    }
}

/// A property definition, owned by a [`TypeDefinition`](super::types::TypeDefinition)'s [`properties`](super::types::TypeDefinition::properties) collection.
#[derive(Debug, Clone)]
pub struct Property<'a> {
    /// All attributes present on the property's declaration.
    pub attributes: Vec<Attribute<'a>>,
    /// Name of the property.
    pub name: Cow<'a, str>,
    /// Getter method for the property, if defined.
    pub getter: Option<Method<'a>>,
    /// Setter method for the property, if defined.
    pub setter: Option<Method<'a>>,
    /// Other methods associated with the property, typically non-standard accessors.
    pub other: Vec<Method<'a>>,
    /// Specifies if the property is a static member of its owning type.
    pub static_member: bool,
    /// Type of the property.
    pub property_type: signature::Parameter,
    /// Parameters the property takes in during access, such as for custom indexers.
    // TODO: metadata representation of indexers
    pub parameters: Vec<signature::Parameter>,
    /// Specifies if the property is named with special meaning for a compiler.
    // TODO: examples
    pub special_name: bool,
    /// Specifies if the property is named with special meaning for the runtime.
    // TODO: examples
    pub runtime_special_name: bool,
    /// Default constant value of the property, if any.
    pub default: Option<Constant>,
}

name_display!(Property<'_>);
impl ResolvedDebug for Property<'_> {
    fn show(&self, res: &Resolution) -> String {
        let mut buf = String::new();

        let accessors: Vec<_> = [self.getter.as_ref(), self.setter.as_ref()]
            .into_iter()
            .flatten()
            .collect();

        let least_restrictive = accessors.iter().map(|m| m.accessibility).max();

        if let Some(access) = least_restrictive {
            write!(buf, "{} ", access).unwrap();
        }

        if accessors.iter().any(|m| m.is_static()) {
            buf.push_str("static ");
        }

        if accessors.iter().any(|m| m.abstract_member) {
            buf.push_str("abstract ");
        } else if accessors.iter().any(|m| m.virtual_member) {
            buf.push_str("virtual ");
        }

        write!(buf, "{} {} {{ ", self.property_type.show(res), self.name).unwrap();

        if let Some(method) = &self.getter {
            if matches!(least_restrictive, Some(a) if method.accessibility < a) {
                write!(buf, "{} ", method.accessibility).unwrap();
            }
            buf.push_str("get; ");
        }
        if let Some(method) = &self.setter {
            if matches!(least_restrictive, Some(a) if method.accessibility < a) {
                write!(buf, "{} ", method.accessibility).unwrap();
            }
            buf.push_str("set; ");
        }

        buf.push('}');

        if let Some(c) = &self.default {
            write!(buf, " = {:?}", c).unwrap();
        }

        buf
    }
}
impl<'a> Property<'a> {
    pub fn new(static_member: bool, name: impl Into<Cow<'a, str>>, property_type: signature::Parameter) -> Self {
        Self {
            attributes: vec![],
            name: name.into(),
            getter: None,
            setter: None,
            other: vec![],
            static_member,
            property_type,
            parameters: vec![],
            special_name: false,
            runtime_special_name: false,
            default: None,
        }
    }
}

#[derive(Debug, Copy, Clone)]
pub enum VtableLayout {
    ReuseSlot,
    NewSlot,
}

/// Metadata associated with a method's parameter (or return type) other than its type signature.
#[derive(Debug, Clone, Default)]
pub struct ParameterMetadata<'a> {
    /// All attributes present on the parameter's declaration.
    pub attributes: Vec<Attribute<'a>>,
    /// Name of the parameter, if specified in metadata.
    pub name: Option<Cow<'a, str>>,
    /// Indicates if the parameter is defined as `in`: that is, it is passed by reference, but modifications are not persisted to the caller.
    pub is_in: bool,
    /// Indicates if the parameter is defined as `out`: that is, it is passed by reference, and modifications are persisted to the caller.
    pub is_out: bool,
    /// Specifies if the parameter is optional.
    pub optional: bool,
    /// Default constant value of the parameter, if any.
    pub default: Option<Constant>,
    /// Specifies the custom marshaling behavior of the parameter, if defined.
    pub marshal: Option<MarshalSpec>,
}
impl Display for ParameterMetadata<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name.as_deref().unwrap_or(""))
    }
}
impl<'a> ParameterMetadata<'a> {
    pub fn name(name: impl Into<Cow<'a, str>>) -> Self {
        Self {
            name: Some(name.into()),
            ..Self::default()
        }
    }

    pub fn marshal(marshal: MarshalSpec) -> Self {
        Self {
            marshal: Some(marshal),
            ..Self::default()
        }
    }
}

#[derive(Debug, Copy, Clone)]
pub enum BodyFormat {
    IL,
    Native,
    Runtime,
}

#[derive(Debug, Copy, Clone)]
pub enum BodyManagement {
    Unmanaged,
    Managed,
}

/// A method definition.
/// - If the method is defined by a property, it is owned by the [`Property`]'s
///   [`getter`](Property::getter)/[`setter`](Property::setter)/[`other`](Property::other) fields.
/// - If the method is defined by an event, it is owned by the [`Event`]'s
///   [`add_listener`](Event::add_listener)/[`remove_listener`](Event::remove_listener)/[`raise_event`](Event::raise_event) fields.
/// - Otherwise, it is a regular type method and owned by a [`TypeDefinition`](super::types::TypeDefinition)'s [`methods`](super::types::TypeDefinition::methods) collection.
#[derive(Debug, Clone)]
pub struct Method<'a> {
    /// All attributes present on the method's declaration.
    pub attributes: Vec<Attribute<'a>>,
    /// Name of the method.
    pub name: Cow<'a, str>,
    /// The IL implementation of the method. Not present for abstract methods,
    /// or if [`ReadOptions::skip_method_bodies`](read::Options::skip_method_bodies) is true at the time of resolution.
    pub body: Option<body::Method>,
    /// Signature of the method, including return type and parameters.
    pub signature: signature::ManagedMethod,
    /// Visibility scope of the method.
    pub accessibility: Accessibility,
    /// Generic type parameters, if the method declares any.
    pub generic_parameters: Vec<generic::Method<'a>>,
    /// Metadata for the method's return type.
    pub return_type_metadata: Option<ParameterMetadata<'a>>,
    /// Metadata for each of the method's parameters.
    pub parameter_metadata: Vec<Option<ParameterMetadata<'a>>>,
    /// Specifies if the method is final and cannot be overridden.
    /// (`final` is a reserved word in Rust, hence the different name for the field.)
    pub sealed: bool,
    /// Specifies if the method is virtual.
    /// (`virtual` is a reserved word in Rust, hence the longer name for the field.)
    pub virtual_member: bool,
    /// This method hides other methods of the base class by name *and* signature if this flag is true, otherwise they are hidden only by name.
    /// See ECMA-335, II.15.4.2.2 (page 184) for more information.
    pub hide_by_sig: bool,
    /// Specifies the position of the method's slot in the vtable.
    pub vtable_layout: VtableLayout,
    /// Indicates if the method can only be overridden when and accessible.
    /// See ECMA-335, II.15.4.2.2 (page 184) for more information.
    pub strict: bool,
    /// Specifies if the method is abstract and doesn't have an implementation.
    /// (`abstract` is a reserved word in Rust, hence the longer name for the field.)
    pub abstract_member: bool,
    /// Specifies if the method is named with special meaning for a compiler.
    // TODO: examples
    pub special_name: bool,
    /// Specifies if the method is named with special meaning for the runtime.
    // TODO: examples
    pub runtime_special_name: bool,
    /// If this method is a P/Invoke binding, specifies the import information.
    pub pinvoke: Option<PInvoke<'a>>,
    /// Runtime security metadata associated with the method.
    pub security: Option<SecurityDeclaration<'a>>,
    /// Indicates that the method calls another method containing security code.
    pub require_sec_object: bool,
    /// Describes the format of the method implementation body.
    pub body_format: BodyFormat,
    /// Indicates whether the method implementation is managed (.NET runtime) or unmanaged (native).
    pub body_management: BodyManagement,
    /// Indicates if the method is a forward reference to another method; i.e., its declaration is present here but its implementation is defined in another type.
    pub forward_ref: bool,
    /// Indicates that the HRESULT signature transformation that takes place during COM interop calls should be suppressed for this method.
    /// Marked as reserved by the ECMA standard.
    pub preserve_sig: bool,
    /// Indicates if the method is single-threaded and thread-safe throughout the body.
    pub synchronized: bool,
    /// Specifies that compilers should not inline this method during optimization.
    pub no_inlining: bool,
    /// Specifies that compilers should not directly optimize this method when generating code.
    pub no_optimization: bool,
}
name_display!(Method<'_>);
impl ResolvedDebug for Method<'_> {
    fn show(&self, res: &Resolution) -> String {
        let mut buf = format!("{} ", self.accessibility);

        if self.is_static() {
            buf.push_str("static ");
        }

        if self.abstract_member {
            buf.push_str("abstract ");
        } else if self.virtual_member {
            buf.push_str("virtual ");
        }

        if self.pinvoke.is_some() {
            buf.push_str("extern ");
        }

        match &self.signature.return_type.1 {
            None => buf.push_str("void "),
            Some(t) => write!(buf, "{} ", t.show(res)).unwrap(),
        }

        write!(
            buf,
            "{}{}({})",
            self.name,
            self.generic_parameters.show(res),
            self.signature
                .parameters
                .iter()
                .map(|p| p.1.show(res))
                .collect::<Vec<_>>()
                .join(", "),
        )
        .unwrap();

        if let Some(constraints) = show_constraints(&self.generic_parameters, res) {
            write!(buf, " {}", constraints).unwrap();
        }

        buf
    }
}
impl<'a> Method<'a> {
    pub fn new(
        access: super::Accessibility,
        signature: signature::ManagedMethod,
        name: impl Into<Cow<'a, str>>,
        body: Option<body::Method>,
    ) -> Self {
        Self {
            attributes: vec![],
            name: name.into(),
            body,
            signature,
            accessibility: Accessibility::Access(access),
            generic_parameters: vec![],
            return_type_metadata: None,
            parameter_metadata: vec![],
            sealed: false,
            virtual_member: false,
            hide_by_sig: true,
            vtable_layout: VtableLayout::ReuseSlot,
            strict: false,
            abstract_member: false,
            special_name: false,
            pinvoke: None,
            runtime_special_name: false,
            security: None,
            require_sec_object: false,
            body_format: BodyFormat::IL,
            body_management: BodyManagement::Managed,
            forward_ref: false,
            preserve_sig: false,
            synchronized: false,
            no_inlining: false,
            no_optimization: false,
        }
    }

    pub fn is_static(&self) -> bool {
        !self.signature.instance
    }

    pub fn constructor(
        access: super::Accessibility,
        parameters: Vec<signature::Parameter>,
        body: Option<body::Method>,
    ) -> Self {
        Self {
            special_name: true,
            runtime_special_name: true,
            ..Self::new(
                access,
                signature::MethodSignature::new(true, signature::ReturnType::VOID, parameters),
                ".ctor",
                body,
            )
        }
    }
}

#[derive(Debug, Copy, Clone)]
pub enum CharacterSet {
    NotSpecified,
    Ansi,
    Unicode,
    Auto,
}

#[derive(Debug, Copy, Clone)]
pub enum UnmanagedCallingConvention {
    Platformapi,
    Cdecl,
    Stdcall,
    Thiscall,
    Fastcall,
}

/// Represents platform invoke (P/Invoke) information defined for a [`Method`](Method::pinvoke) or [`Field`](Field::pinvoke).
#[derive(Debug, Clone)]
pub struct PInvoke<'a> {
    /// Specifies if the imported function should be searched for with C++ name mangling rules or not.
    pub no_mangle: bool,
    /// Defines how strings should be marshaled for the function call. Also affects name mangling.
    pub character_set: CharacterSet,
    /// Indicates if the function sets a global error value (Windows `SetLastError` or Unix `errno`) before returning to report errors.
    pub supports_last_error: bool,
    /// Describes the calling convention of the unmanaged function.
    pub calling_convention: UnmanagedCallingConvention,
    /// The name of the unmanaged function to be invoked.
    pub import_name: Cow<'a, str>,
    /// The scope from which the unmanaged function is imported, typically a DLL or shared library.
    pub import_scope: ModuleRefIndex,
}
impl<'a> PInvoke<'a> {
    pub fn new(import_scope: ModuleRefIndex, import_name: impl Into<Cow<'a, str>>) -> Self {
        Self {
            no_mangle: false,
            character_set: CharacterSet::NotSpecified,
            supports_last_error: false,
            calling_convention: UnmanagedCallingConvention::Platformapi,
            import_name: import_name.into(),
            import_scope,
        }
    }
}

/// Outlines the possible locations where an externally defined method could be, thus specifying the parent type for an [`ExternalMethodReference`].

#[derive(Debug, Clone, From)]
pub enum MethodReferenceParent {
    /// The method is part of a specific type (e.g., an instance method of a class or a static method).
    Type(MethodType),
    /// The method is defined at the module level, outside of any specific type.
    Module(ModuleRefIndex),
    /// The method is defined in this type, but as an instantiation of varargs.
    VarargMethod(MethodIndex),
}

/// A reference to a method whose owning type is defined externally to the current DLL or module.
/// Also used for calls to vararg methods.
#[derive(Debug, Clone)]
pub struct ExternalMethodReference<'a> {
    /// All attributes presents on this method reference's metadata record.
    pub attributes: Vec<Attribute<'a>>,
    /// Parent location of the method reference. Usually the method's owning type.
    pub parent: MethodReferenceParent,
    /// Name of the method.
    pub name: Cow<'a, str>,
    /// Signature of the method.
    pub signature: signature::ManagedMethod,
}

name_display!(ExternalMethodReference<'_>);
impl<'a> ExternalMethodReference<'a> {
    pub fn new(
        parent: MethodReferenceParent,
        name: impl Into<Cow<'a, str>>,
        signature: signature::ManagedMethod,
    ) -> Self {
        Self {
            attributes: vec![],
            parent,
            name: name.into(),
            signature,
        }
    }
}

#[derive(Debug, Copy, Clone, From, Eq, PartialEq)]
pub enum UserMethod {
    Definition(MethodIndex),
    Reference(MethodRefIndex),
}
impl ResolvedDebug for UserMethod {
    fn show(&self, res: &Resolution) -> String {
        let signature;
        let parent_name;
        let method_name: &str;

        match self {
            UserMethod::Definition(i) => {
                let method = &res[*i];
                signature = &method.signature;
                parent_name = res[i.parent_type].nested_type_name(res);
                method_name = &method.name;
            }
            UserMethod::Reference(i) => {
                let r = &res[*i];
                signature = &r.signature;
                method_name = &r.name;

                use MethodReferenceParent::*;
                parent_name = match &r.parent {
                    Type(t) => t.show(res),
                    Module(m) => res[*m].name.to_string(),
                    VarargMethod(i) => res[i.parent_type].nested_type_name(res),
                }
            }
        }

        let ret_type = signature.return_type.show(res);

        match &signature.varargs {
            Some(v) => format!(
                "vararg {} {}.{}({})",
                ret_type,
                parent_name,
                method_name,
                signature
                    .parameters
                    .iter()
                    .map(|p| p.show(res))
                    .chain(std::iter::once("...".to_string()))
                    .chain(v.iter().map(|p| p.show(res)))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            None => signature.show_with_name(res, format!("{}.{}", parent_name, method_name)),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct GenericMethodInstantiation {
    pub base: UserMethod,
    pub parameters: Vec<MethodType>,
}

#[derive(Debug, Clone, From, Eq, PartialEq)]
pub enum MethodSource {
    User(#[nested(MethodIndex, MethodRefIndex)] UserMethod),
    Generic(GenericMethodInstantiation),
}
impl ResolvedDebug for MethodSource {
    fn show(&self, res: &Resolution) -> String {
        use MethodSource::*;
        match self {
            User(u) => u.show(res),
            Generic(g) => format!(
                "({})<{}>",
                g.base.show(res),
                g.parameters.iter().map(|p| p.show(res)).collect::<Vec<_>>().join(", ")
            ),
        }
    }
}

#[derive(Debug, Clone)]
pub enum Constant {
    Boolean(bool),
    Char(u16), // not necessarily valid UTF-16
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
    String(Vec<u16>), // ditto
    Null,
}

/// An event definition, owned by a [`TypeDefinition`](super::types::TypeDefinition)'s [`events`](super::types::TypeDefinition::events) collection.
#[derive(Debug, Clone)]
pub struct Event<'a> {
    /// All attributes present on the event's declaration.
    pub attributes: Vec<Attribute<'a>>,
    /// Name of the event.
    pub name: Cow<'a, str>,
    /// The delegate type that describes the method signature of a handler for this event.
    // TODO: explain delegate types, Func/Action, etc
    pub delegate_type: MemberType,
    /// The method used to add a listener or handler to this event.
    pub add_listener: Method<'a>,
    /// The method used to remove a listener or handler from this event.
    pub remove_listener: Method<'a>,
    /// The method used to raise or trigger the event, if explicitly defined.
    pub raise_event: Option<Method<'a>>,
    /// Any other methods associated with this event, often related to its internal handling.
    pub other: Vec<Method<'a>>,
    /// Specifies if the event is named with special meaning for a compiler.
    // TODO: examples
    pub special_name: bool,
    /// Specifies if the event is named with special meaning for the runtime.
    // TODO: examples
    pub runtime_special_name: bool,
}
name_display!(Event<'_>);
impl ResolvedDebug for Event<'_> {
    fn show(&self, res: &Resolution) -> String {
        format!(
            "{} {}{}event {} {}",
            self.add_listener.accessibility,
            if self.add_listener.is_static() { "static " } else { "" },
            if self.add_listener.abstract_member {
                "abstract "
            } else if self.add_listener.virtual_member {
                "virtual "
            } else {
                ""
            },
            self.delegate_type.show(res),
            self.name
        )
    }
}
impl<'a> Event<'a> {
    pub fn new(
        name: impl Into<Cow<'a, str>>,
        delegate_type: MemberType,
        add_listener: Method<'a>,
        remove_listener: Method<'a>,
    ) -> Self {
        Self {
            attributes: vec![],
            name: name.into(),
            delegate_type,
            add_listener,
            remove_listener,
            raise_event: None,
            other: vec![],
            special_name: false,
            runtime_special_name: false,
        }
    }
}
