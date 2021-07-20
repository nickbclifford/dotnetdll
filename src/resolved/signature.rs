use super::types::{CustomTypeModifier, MethodType};
use crate::{
    binary::signature::kinds::{CallingConvention, StandAloneCallingConvention},
    resolution::Resolution,
    resolved::ResolvedDebug,
};
use std::fmt::Write;

#[derive(Debug, Clone)]
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

#[derive(Debug, Clone)]
pub struct Parameter(pub Vec<CustomTypeModifier>, pub ParameterType);
impl ResolvedDebug for Parameter {
    fn show(&self, res: &Resolution) -> String {
        let mut buf = String::new();
        for c in self.0.iter() {
            write!(buf, "{} ", c.show(res)).unwrap();
        }

        write!(buf, "{}", self.1.show(res)).unwrap();

        buf
    }
}

#[derive(Debug, Clone)]
pub struct ReturnType(pub Vec<CustomTypeModifier>, pub Option<ParameterType>);
impl ResolvedDebug for ReturnType {
    fn show(&self, res: &Resolution) -> String {
        let mut buf = String::new();
        for c in self.0.iter() {
            write!(buf, "{} ", c.show(res)).unwrap();
        }

        match &self.1 {
            Some(t) => write!(buf, "{}", t.show(res)).unwrap(),
            None => buf.push_str("void"),
        }

        buf
    }
}

#[derive(Debug, Clone)]
pub struct MethodSignature<CallConv> {
    pub instance: bool,
    pub explicit_this: bool,
    pub calling_convention: CallConv,
    pub parameters: Vec<Parameter>,
    pub return_type: ReturnType,
    pub varargs: Option<Vec<Parameter>>,
}
impl<T: std::fmt::Debug> ResolvedDebug for MethodSignature<T> {
    fn show(&self, res: &Resolution) -> String {
        let mut buf = format!("[{:?}] ", self.calling_convention);

        if !self.instance {
            buf.push_str("static ");
        }

        write!(
            buf,
            "{} ({})",
            self.return_type.show(res),
            self.show_parameters(res)
        )
        .unwrap();

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
