use std::borrow::Cow;
use super::{
    attribute::{Attribute, SecurityDeclaration},
    body,
    generic::{show_constraints, MethodGeneric},
    signature,
    types::{CustomTypeModifier, MemberType, MethodType},
    ResolvedDebug,
};
use crate::binary::signature::kinds::MarshalSpec;
use crate::resolution::*;
use dotnetdll_macros::From;
use std::fmt::{Display, Formatter, Write};

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

#[derive(Debug, Clone)]
pub struct Field<'a> {
    pub attributes: Vec<Attribute<'a>>,
    pub name: &'a str,
    pub type_modifiers: Vec<CustomTypeModifier>,
    pub return_type: MemberType,
    pub accessibility: Accessibility,
    pub static_member: bool,
    pub init_only: bool,
    pub literal: bool,
    pub default: Option<Constant>,
    pub not_serialized: bool,
    pub special_name: bool,
    pub pinvoke: Option<PInvoke<'a>>,
    pub runtime_special_name: bool,
    pub offset: Option<usize>,
    pub marshal: Option<MarshalSpec>,
    pub initial_value: Option<&'a [u8]>,
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
    pub const fn new(access: super::Accessibility, name: &'a str, return_type: MemberType) -> Self {
        Self {
            attributes: vec![],
            name,
            type_modifiers: vec![],
            return_type,
            accessibility: Accessibility::Access(access),
            static_member: false,
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
}

#[derive(Debug, Clone, From)]
pub enum FieldReferenceParent {
    Type(MethodType),
    Module(ModuleRefIndex),
}

#[derive(Debug, Clone)]
pub struct ExternalFieldReference<'a> {
    pub attributes: Vec<Attribute<'a>>,
    pub parent: FieldReferenceParent,
    pub name: &'a str,
    pub custom_modifiers: Vec<CustomTypeModifier>,
    pub return_type: MemberType,
}
name_display!(ExternalFieldReference<'_>);

#[derive(Debug, Copy, Clone, From)]
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

#[derive(Debug, Clone)]
pub struct Property<'a> {
    pub attributes: Vec<Attribute<'a>>,
    pub name: &'a str,
    pub getter: Option<Method<'a>>,
    pub setter: Option<Method<'a>>,
    pub other: Vec<Method<'a>>,
    pub property_type: signature::Parameter, // properties can be ref as well
    pub special_name: bool,
    pub runtime_special_name: bool,
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
    pub const fn new(name: &'a str, property_type: signature::Parameter) -> Self {
        Self {
            attributes: vec![],
            name,
            getter: None,
            setter: None,
            other: vec![],
            property_type,
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
impl<'a> ParameterMetadata<'a> {
    pub const fn name(name: &'a str) -> Self {
        Self {
            attributes: vec![],
            name,
            is_in: false,
            is_out: false,
            optional: false,
            default: None,
            marshal: None,
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

#[derive(Debug, Clone)]
pub struct Method<'a> {
    pub attributes: Vec<Attribute<'a>>,
    pub name: Cow<'a, str>,
    pub body: Option<body::Method>,
    pub signature: signature::ManagedMethod,
    pub accessibility: Accessibility,
    pub generic_parameters: Vec<MethodGeneric<'a>>,
    pub return_type_metadata: Option<ParameterMetadata<'a>>,
    pub parameter_metadata: Vec<Option<ParameterMetadata<'a>>>,
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
    pub const fn new(
        access: super::Accessibility,
        signature: signature::ManagedMethod,
        name: Cow<'a, str>,
        body: Option<body::Method>,
    ) -> Self {
        Self {
            attributes: vec![],
            name,
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

#[derive(Debug, Copy, Clone)]
pub struct PInvoke<'a> {
    pub no_mangle: bool,
    pub character_set: CharacterSet,
    pub supports_last_error: bool,
    pub calling_convention: UnmanagedCallingConvention,
    pub import_name: &'a str,
    pub import_scope: ModuleRefIndex,
}

#[derive(Debug, Clone, From)]
pub enum MethodReferenceParent {
    Type(MethodType),
    Module(ModuleRefIndex),
    VarargMethod(MethodIndex),
}

#[derive(Debug, Clone)]
pub struct ExternalMethodReference<'a> {
    pub attributes: Vec<Attribute<'a>>,
    pub parent: MethodReferenceParent,
    pub name: &'a str,
    pub signature: signature::ManagedMethod,
}
name_display!(ExternalMethodReference<'_>);
impl<'a> ExternalMethodReference<'a> {
    pub const fn new(parent: MethodReferenceParent, name: &'a str, signature: signature::ManagedMethod) -> Self {
        Self {
            attributes: vec![],
            parent,
            name,
            signature,
        }
    }
}

#[derive(Debug, Copy, Clone, From)]
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
                method_name = r.name;

                use MethodReferenceParent::*;
                parent_name = match &r.parent {
                    Type(t) => t.show(res),
                    Module(m) => res[*m].name.to_string(),
                    VarargMethod(i) => res[i.parent_type].nested_type_name(res),
                }
            }
        }

        let mut buf = if signature.instance {
            String::new()
        } else {
            String::from("static ")
        };

        let ret_type = signature.return_type.show(res);

        match &signature.varargs {
            Some(v) => write!(
                buf,
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
            None => write!(
                buf,
                "{} {}.{}({})",
                ret_type,
                parent_name,
                method_name,
                signature.show_parameters(res)
            ),
        }
        .unwrap();

        buf
    }
}

#[derive(Debug, Clone)]
pub struct GenericMethodInstantiation {
    pub base: UserMethod,
    pub parameters: Vec<MethodType>,
}

#[derive(Debug, Clone, From)]
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

#[derive(Debug, Clone)]
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
    pub const fn new(
        name: &'a str,
        delegate_type: MemberType,
        add_listener: Method<'a>,
        remove_listener: Method<'a>,
    ) -> Self {
        Self {
            attributes: vec![],
            name,
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
