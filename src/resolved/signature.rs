use super::types::{CustomTypeModifier, MethodType};
use crate::binary::signature::kinds::{CallingConvention, StandAloneCallingConvention};

#[derive(Debug, Clone)]
pub enum ParameterType<'a> {
    Value(MethodType<'a>),
    Ref(MethodType<'a>),
    TypedReference,
}

#[derive(Debug, Clone)]
pub struct Parameter<'a>(pub Option<CustomTypeModifier<'a>>, pub ParameterType<'a>);

#[derive(Debug, Clone)]
pub struct ReturnType<'a>(
    pub Option<CustomTypeModifier<'a>>,
    pub Option<ParameterType<'a>>,
);

#[derive(Debug, Clone)]
pub struct MethodSignature<'a, CallConv> {
    pub instance: bool,
    pub explicit_this: bool,
    pub calling_convention: CallConv,
    pub parameters: Vec<Parameter<'a>>,
    pub return_type: ReturnType<'a>,
    pub varargs: Option<Vec<Parameter<'a>>>,
}

pub type ManagedMethod<'a> = MethodSignature<'a, CallingConvention>;
pub type MaybeUnmanagedMethod<'a> = MethodSignature<'a, StandAloneCallingConvention>;
