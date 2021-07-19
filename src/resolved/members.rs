use std::{
    cell::RefCell,
    fmt::{Display, Formatter, Write},
    rc::Rc,
};

use crate::binary::signature::kinds::MarshalSpec;
use crate::resolution::{MethodIndex, Resolution};

use super::{
    attribute::{Attribute, SecurityDeclaration},
    body,
    generic::{show_constraints, MethodGeneric},
    module::ExternalModuleReference,
    signature,
    types::{CustomTypeModifier, MemberType, MethodType, TypeSource},
    ResolvedDebug,
};

macro_rules! name_display {
    ($i:ty) => {
        impl Display for $i {
            fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
                write!(f, "{}", self.name)
            }
        }
    };
}

#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq)]
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
    pub pinvoke: Option<PInvoke<'a>>,
    pub runtime_special_name: bool,
    pub offset: Option<usize>,
    pub marshal: Option<MarshalSpec>,
    pub start_of_initial_value: Option<&'a [u8]>,
}
name_display!(Field<'_>);
impl ResolvedDebug for Field<'_> {
    fn show(&self, res: &Resolution) -> String {
        format!(
            "{} {}{} {}",
            self.accessibility,
            if self.static_member { "static " } else { "" },
            self.return_type.show(res),
            self.name
        )
    }
}

#[derive(Debug)]
pub enum FieldReferenceParent<'a> {
    Type(TypeSource<MethodType>),
    Module(Rc<RefCell<ExternalModuleReference<'a>>>),
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
    Definition { parent: usize, field: usize },
    Reference(Rc<RefCell<ExternalFieldReference<'a>>>),
}
impl Display for FieldSource<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        use FieldSource::*;

        match self {
            Definition { field, .. } => write!(f, "{}", field),
            Reference(r) => write!(f, "{}", r.borrow()),
        }
    }
}
impl ResolvedDebug for FieldSource<'_> {
    fn show(&self, res: &Resolution) -> String {
        use FieldSource::*;

        match self {
            Definition { parent, field } => {
                let t = &res.type_definitions[*parent];
                format!("{}.{}", t.type_name(), t.fields[*field].name)
            }
            Reference(rc) => {
                use FieldReferenceParent::*;

                let r = rc.borrow();
                format!(
                    "{}.{}",
                    match &r.parent {
                        Type(t) => t.show(res),
                        Module(m) => m.borrow().name.to_string(),
                    },
                    r.name
                )
            }
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
impl ResolvedDebug for Property<'_> {
    fn show(&self, res: &Resolution) -> String {
        let mut buf = String::new();

        let accessors: Vec<_> =
            std::array::IntoIter::new([self.getter.as_ref(), self.setter.as_ref()])
                .flatten()
                .collect();

        let least_restrictive = accessors.iter().map(|m| m.accessibility).max();

        if let Some(access) = least_restrictive {
            write!(buf, "{} ", access).unwrap();
        }

        if accessors.iter().any(|m| m.static_member) {
            buf.push_str("static ");
        }

        if accessors.iter().any(|m| m.abstract_member) {
            buf.push_str("abstract ");
        } else if accessors.iter().any(|m| m.virtual_member) {
            buf.push_str("virtual ");
        }

        write!(buf, "{} {} {{ ", self.return_type.show(res), self.name).unwrap();

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

        buf
    }
}

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
impl ResolvedDebug for Method<'_> {
    fn show(&self, res: &Resolution) -> String {
        let mut buf = format!("{} ", self.accessibility);

        if self.static_member {
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
    pub import_scope: Rc<RefCell<ExternalModuleReference<'a>>>,
}

#[derive(Debug)]
pub enum MethodReferenceParent<'a> {
    Type(TypeSource<MethodType>),
    Module(Rc<RefCell<ExternalModuleReference<'a>>>),
    VarargMethod(MethodIndex),
}

#[derive(Debug)]
pub struct ExternalMethodReference<'a> {
    pub attributes: Vec<Attribute<'a>>,
    pub parent: MethodReferenceParent<'a>,
    pub name: &'a str,
    pub signature: signature::ManagedMethod,
}
name_display!(ExternalMethodReference<'_>);

#[derive(Debug, Clone)]
pub enum UserMethod<'a> {
    Definition(MethodIndex),
    Reference(Rc<RefCell<ExternalMethodReference<'a>>>),
}
impl ResolvedDebug for UserMethod<'_> {
    fn show(&self, res: &Resolution) -> String {
        let signature;
        let parent_name;
        let method_name;

        match self {
            UserMethod::Definition(i) => {
                let method = &res[*i];
                signature = method.signature.clone();
                parent_name = res.type_definitions[i.parent_type].type_name();
                method_name = method.name;
            }
            UserMethod::Reference(rc) => {
                let r = rc.borrow();
                signature = r.signature.clone();
                method_name = r.name;

                use MethodReferenceParent::*;
                parent_name = match &r.parent {
                    Type(t) => t.show(res),
                    Module(m) => m.borrow().name.to_string(),
                    VarargMethod(i) => res.type_definitions[i.parent_type].type_name(),
                }
            }
        }

        let mut buf = if signature.instance {
            String::new()
        } else {
            String::from("static ")
        };

        let ret_type = signature.return_type.show(res);

        match signature.varargs {
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

#[derive(Debug)]
pub struct GenericMethodInstantiation<'a> {
    pub base: UserMethod<'a>,
    pub parameters: Vec<MethodType>,
}

#[derive(Debug)]
pub enum MethodSource<'a> {
    User(UserMethod<'a>),
    Generic(GenericMethodInstantiation<'a>),
}
impl ResolvedDebug for MethodSource<'_> {
    fn show(&self, res: &Resolution) -> String {
        use MethodSource::*;
        match self {
            User(u) => u.show(res),
            Generic(g) => format!(
                "({})<{}>",
                g.base.show(res),
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
impl ResolvedDebug for Event<'_> {
    fn show(&self, res: &Resolution) -> String {
        format!(
            "{} {}{}event {} {}",
            self.add_listener.accessibility,
            if self.add_listener.static_member {
                "static "
            } else {
                ""
            },
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
