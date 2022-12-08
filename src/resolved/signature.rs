pub use crate::binary::signature::kinds::{CallingConvention, StandAloneCallingConvention};
use crate::{
    resolution::Resolution,
    resolved::{
        types::{CustomTypeModifier, MethodType},
        ResolvedDebug,
    },
};
pub use dotnetdll_macros::msig;
use std::fmt::{Debug, Display, Write};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ParameterType {
    Value(MethodType),
    Ref(MethodType),
    TypedReference,
}
impl ResolvedDebug for ParameterType {
    fn show(&self, res: &Resolution) -> String {
        use ParameterType::*;
        match self {
            Value(t) => t.show(res),
            Ref(t) => format!("ref {}", t.show(res)),
            TypedReference => "System.TypedReference".to_string(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Parameter(pub Vec<CustomTypeModifier>, pub ParameterType);
impl ResolvedDebug for Parameter {
    fn show(&self, res: &Resolution) -> String {
        let mut buf = String::new();
        for c in &self.0 {
            write!(buf, "{} ", c.show(res)).unwrap();
        }

        write!(buf, "{}", self.1.show(res)).unwrap();

        buf
    }
}
impl Parameter {
    pub const fn new(t: ParameterType) -> Self {
        Parameter(vec![], t)
    }

    pub const fn value(t: MethodType) -> Self {
        Self::new(ParameterType::Value(t))
    }

    pub const fn reference(t: MethodType) -> Self {
        Self::new(ParameterType::Ref(t))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ReturnType(pub Vec<CustomTypeModifier>, pub Option<ParameterType>);
impl ResolvedDebug for ReturnType {
    fn show(&self, res: &Resolution) -> String {
        let mut buf = String::new();
        for c in &self.0 {
            write!(buf, "{} ", c.show(res)).unwrap();
        }

        match &self.1 {
            Some(t) => write!(buf, "{}", t.show(res)).unwrap(),
            None => buf.push_str("void"),
        }

        buf
    }
}
impl ReturnType {
    pub const VOID: Self = ReturnType(vec![], None);

    pub const fn new(t: ParameterType) -> Self {
        ReturnType(vec![], Some(t))
    }

    pub const fn value(t: MethodType) -> Self {
        Self::new(ParameterType::Value(t))
    }

    pub const fn reference(t: MethodType) -> Self {
        Self::new(ParameterType::Ref(t))
    }
}

#[allow(clippy::module_name_repetitions)]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MethodSignature<CallConv> {
    pub instance: bool,
    pub explicit_this: bool,
    pub calling_convention: CallConv,
    pub parameters: Vec<Parameter>,
    pub return_type: ReturnType,
    pub varargs: Option<Vec<Parameter>>,
}
impl<T: Debug> ResolvedDebug for MethodSignature<T> {
    fn show(&self, res: &Resolution) -> String {
        self.show_with_name(res, "")
    }
}
impl<T: Debug> MethodSignature<T> {
    pub fn show_with_name(&self, res: &Resolution, name: impl Display) -> String {
        let mut buf = format!("[{:?}] ", self.calling_convention);

        if !self.instance {
            buf.push_str("static ");
        }

        write!(buf, "{} {}({})", self.return_type.show(res), name, self.show_parameters(res)).unwrap();

        buf
    }
}
impl<T> MethodSignature<T> {
    pub fn show_parameters(&self, res: &Resolution) -> String {
        self.parameters
            .iter()
            .map(|p| p.show(res))
            .collect::<Vec<_>>()
            .join(", ")
    }
}
pub type ManagedMethod = MethodSignature<CallingConvention>;
pub type MaybeUnmanagedMethod = MethodSignature<StandAloneCallingConvention>;
impl ManagedMethod {
    pub const fn new(instance: bool, return_type: ReturnType, parameters: Vec<Parameter>) -> Self {
        Self {
            instance,
            explicit_this: false,
            calling_convention: CallingConvention::Default,
            parameters,
            return_type,
            varargs: None,
        }
    }

    pub const fn instance(return_type: ReturnType, parameters: Vec<Parameter>) -> Self {
        Self::new(true, return_type, parameters)
    }

    pub const fn static_member(return_type: ReturnType, parameters: Vec<Parameter>) -> Self {
        Self::new(false, return_type, parameters)
    }
}
