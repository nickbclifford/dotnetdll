use super::types::{CustomTypeModifier, MethodType};
use crate::binary::signature::kinds::{CallingConvention, StandAloneCallingConvention};

#[derive(Debug, Clone)]
pub enum ParameterType {
    Value(MethodType),
    Ref(MethodType),
    TypedReference,
}

#[derive(Debug, Clone)]
pub struct Parameter(pub Option<CustomTypeModifier>, pub ParameterType);

#[derive(Debug, Clone)]
pub struct ReturnType(
    pub Option<CustomTypeModifier>,
    pub Option<ParameterType>,
);

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
