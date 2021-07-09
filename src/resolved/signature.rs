use super::types::{CustomTypeModifier, MethodType};
use crate::binary::signature::kinds::{CallingConvention, StandAloneCallingConvention};
use crate::resolution::Resolution;
use crate::resolved::ResolvedDebug;

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
pub struct Parameter(pub Option<CustomTypeModifier>, pub ParameterType);

#[derive(Debug, Clone)]
pub struct ReturnType(pub Option<CustomTypeModifier>, pub Option<ParameterType>);

#[derive(Debug, Clone)]
pub struct MethodSignature<CallConv> {
    pub instance: bool,
    pub explicit_this: bool,
    pub calling_convention: CallConv,
    pub parameters: Vec<Parameter>,
    pub return_type: ReturnType,
    pub varargs: Option<Vec<Parameter>>,
}

pub type ManagedMethod = MethodSignature<CallingConvention>;
pub type MaybeUnmanagedMethod = MethodSignature<StandAloneCallingConvention>;
