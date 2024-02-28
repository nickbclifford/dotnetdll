use std::fmt::{Debug, Display, Write};

pub use dotnetdll_macros::msig;

pub use crate::binary::signature::kinds::{CallingConvention, StandAloneCallingConvention};
use crate::{
    resolution::Resolution,
    resolved::{types::CustomTypeModifier, ResolvedDebug},
};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ParameterType<InnerType> {
    Value(InnerType),
    Ref(InnerType),
    TypedReference,
}
impl<T: ResolvedDebug> ResolvedDebug for ParameterType<T> {
    fn show(&self, res: &Resolution) -> String {
        use ParameterType::*;
        match self {
            Value(t) => t.show(res),
            Ref(t) => format!("ref {}", t.show(res)),
            TypedReference => "System.TypedReference".to_string(),
        }
    }
}
impl<A> ParameterType<A> {
    pub fn map<B>(self, f: impl FnMut(A) -> B) -> ParameterType<B> {
        use ParameterType::*;
        match self {
            Value(t) => Value(f(t)),
            Ref(t) => Ref(f(t)),
            TypedReference => TypedReference,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Parameter<InnerType>(pub Vec<CustomTypeModifier>, pub ParameterType<InnerType>);
impl<T: ResolvedDebug> ResolvedDebug for Parameter<T> {
    fn show(&self, res: &Resolution) -> String {
        let mut buf = String::new();
        for c in &self.0 {
            write!(buf, "{} ", c.show(res)).unwrap();
        }

        write!(buf, "{}", self.1.show(res)).unwrap();

        buf
    }
}
impl<T> Parameter<T> {
    pub const fn new(t: ParameterType<T>) -> Self {
        Parameter(vec![], t)
    }

    pub const fn value(t: T) -> Self {
        Self::new(ParameterType::Value(t))
    }

    pub const fn reference(t: T) -> Self {
        Self::new(ParameterType::Ref(t))
    }

    pub fn map<B>(self, f: impl FnMut(T) -> B) -> Parameter<B> {
        Parameter(self.0, self.1.map(f))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ReturnType<InnerType>(pub Vec<CustomTypeModifier>, pub Option<ParameterType<InnerType>>);
impl<T: ResolvedDebug> ResolvedDebug for ReturnType<T> {
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
impl<T> ReturnType<T> {
    pub const VOID: Self = ReturnType(vec![], None);

    pub const fn new(t: ParameterType<T>) -> Self {
        ReturnType(vec![], Some(t))
    }

    pub const fn value(t: T) -> Self {
        Self::new(ParameterType::Value(t))
    }

    pub const fn reference(t: T) -> Self {
        Self::new(ParameterType::Ref(t))
    }

    pub fn map<B>(self, f: impl FnMut(T) -> B) -> ReturnType<B> {
        ReturnType(self.0, self.1.map(|p| p.map(f)))
    }
}

#[allow(clippy::module_name_repetitions)]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MethodSignature<CallConv, InnerType> {
    pub instance: bool,
    pub explicit_this: bool,
    pub calling_convention: CallConv,
    pub parameters: Vec<Parameter<InnerType>>,
    pub return_type: ReturnType<InnerType>,
    pub varargs: Option<Vec<Parameter<InnerType>>>,
}
impl<C: Debug, T: Debug> ResolvedDebug for MethodSignature<C, T> {
    fn show(&self, res: &Resolution) -> String {
        self.show_with_name(res, "")
    }
}
impl<C: Debug, T: Debug> MethodSignature<C, T> {
    pub fn show_with_name(&self, res: &Resolution, name: impl Display) -> String {
        let mut buf = format!("[{:?}] ", self.calling_convention);
        // ignore default convention for managed method signatures (will keep for maybe unmanaged signatures)
        if buf == "[Default] " {
            buf.clear();
        }

        if !self.instance {
            buf.push_str("static ");
        }

        write!(
            buf,
            "{} {}({})",
            self.return_type.show(res),
            name,
            self.show_parameters(res)
        )
        .unwrap();

        buf
    }
}
impl<C, T: ResolvedDebug> MethodSignature<C, T> {
    pub fn show_parameters(&self, res: &Resolution) -> String {
        self.parameters
            .iter()
            .map(|p| p.show(res))
            .collect::<Vec<_>>()
            .join(", ")
    }
}
pub type ManagedMethod<T> = MethodSignature<CallingConvention, T>;
pub type MaybeUnmanagedMethod<T> = MethodSignature<StandAloneCallingConvention, T>;
impl<T> ManagedMethod<T> {
    pub const fn new(instance: bool, return_type: ReturnType<T>, parameters: Vec<Parameter<T>>) -> Self {
        Self {
            instance,
            explicit_this: false,
            calling_convention: CallingConvention::Default,
            parameters,
            return_type,
            varargs: None,
        }
    }

    pub const fn instance(return_type: ReturnType<T>, parameters: Vec<Parameter<T>>) -> Self {
        Self::new(true, return_type, parameters)
    }

    pub const fn static_member(return_type: ReturnType<T>, parameters: Vec<Parameter<T>>) -> Self {
        Self::new(false, return_type, parameters)
    }
}
