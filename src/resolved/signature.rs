//! Method signature types and the [`msig!`](msig) convenience macro.
//!
//! ## Constructing signatures with `msig!`
//!
//! The [`msig!`](msig) proc macro provides a compact syntax for building managed method
//! signatures.
//!
//! ```rust
//! use dotnetdll::prelude::*;
//!
//! let sig: ManagedMethod<MethodType> = msig! { static void (int, string) };
//! let sig: ManagedMethod<MethodType> = msig! { string (ref int) };
//! ```
//!
//! ## Splicing existing values: `#var` (move) and `@var` (clone)
//!
//! In places where `msig!` expects a type, you can splice an existing Rust value into the macro
//! input:
//!
//! - `#var` expands to `var` (moves it into the generated expression)
//! - `@var` expands to `var.clone()`
//!
//! ```rust
//! use dotnetdll::prelude::*;
//!
//! let elem: MethodType = ctype! { string[] };
//! let _sig: ManagedMethod<MethodType> = msig! { void (@elem, @elem) };
//! let _still_have_elem = elem;
//! ```

use std::fmt::{Debug, Display, Write};

/// Construct a [`ManagedMethod`] signature using a compact ILAsm-style syntax.
///
/// #### Examples
///
/// ```rust
/// use dotnetdll::prelude::*;
///
/// // Static method returning void with two parameters
/// let sig: ManagedMethod<MethodType> = msig! { static void (int, string) };
///
/// // Instance method returning string
/// let sig: ManagedMethod<MethodType> = msig! { string (bool) };
///
/// // Method with ref parameter
/// let sig: ManagedMethod<MethodType> = msig! { void (ref int, string) };
/// # let _ = sig;
/// ```
///
/// #### Splicing existing values: `#var` (move) and `@var` (clone)
///
/// In places where `msig!` expects a type, you can splice an existing Rust value into the macro
/// input:
///
/// - `#var` expands to `var` (moves it into the generated expression)
/// - `@var` expands to `var.clone()`
///
/// ```rust
/// use dotnetdll::prelude::*;
///
/// let elem: MethodType = ctype! { string[] };
/// let _sig: ManagedMethod<MethodType> = msig! { void (@elem, @elem) };
/// let _still_have_elem = elem;
/// ```
pub use dotnetdll_macros::msig;

pub use crate::binary::signature::kinds::{CallingConvention, StandAloneCallingConvention};
use crate::{
    resolution::Resolution,
    resolved::{types::CustomTypeModifier, ResolvedDebug},
};

/// Specifies the type of a parameter or return value in a method signature.
///
/// See ECMA-335, II.23.2.10 (page 264) for more information.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ParameterType<InnerType> {
    /// A value of the specified type.
    Value(InnerType),
    /// A managed reference to the specified type.
    Ref(InnerType),
    /// A typed reference, which contains both a managed pointer and a runtime type handle.
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
    pub fn map<B>(self, f: impl FnOnce(A) -> B) -> ParameterType<B> {
        use ParameterType::*;
        match self {
            Value(t) => Value(f(t)),
            Ref(t) => Ref(f(t)),
            TypedReference => TypedReference,
        }
    }
}

/// Metadata for a parameter in a method signature.
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

    pub fn map<B>(self, f: impl FnOnce(T) -> B) -> Parameter<B> {
        Parameter(self.0, self.1.map(f))
    }
}

/// Metadata for the return type of a method signature.
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
    /// Returns the primitive `void` return type.
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

    pub fn map<B>(self, f: impl FnOnce(T) -> B) -> ReturnType<B> {
        ReturnType(self.0, self.1.map(|p| p.map(f)))
    }
}

/// A method signature, defining the calling convention, return type, and parameters.
///
/// The `InnerType` type parameter represents the types allowed in the return type and parameter list.
/// See [`crate::resolved::types::BaseType`]'s documentation for more information.
///
/// See ECMA-335, II.23.2.1 (page 260) for more information.
#[allow(clippy::module_name_repetitions)]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MethodSignature<CallConv, InnerType> {
    /// If true, the method is an instance method (requires a `this` pointer).
    pub instance: bool,
    /// If true, the `this` pointer is explicitly included in the signature.
    pub explicit_this: bool,
    /// Calling convention of the method.
    pub calling_convention: CallConv,
    /// Parameters of the method.
    pub parameters: Vec<Parameter<InnerType>>,
    /// Return type of the method.
    pub return_type: ReturnType<InnerType>,
    /// Additional variable arguments (for vararg calling conventions).
    pub varargs: Option<Vec<Parameter<InnerType>>>,
}
impl<C: Debug, T: ResolvedDebug> ResolvedDebug for MethodSignature<C, T> {
    fn show(&self, res: &Resolution) -> String {
        self.show_with_name(res, "")
    }
}
impl<C: Debug, T: ResolvedDebug> MethodSignature<C, T> {
    /// Returns a human-readable representation of the signature with the specified method name.
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
    /// Returns a human-readable representation of the method's parameters.
    pub fn show_parameters(&self, res: &Resolution) -> String {
        self.parameters
            .iter()
            .map(|p| p.show(res))
            .collect::<Vec<_>>()
            .join(", ")
    }
}
impl<C, T> MethodSignature<C, T> {
    pub fn map<B>(self, mut f: impl FnMut(T) -> B) -> MethodSignature<C, B> {
        MethodSignature {
            instance: self.instance,
            explicit_this: self.explicit_this,
            calling_convention: self.calling_convention,
            parameters: self.parameters.into_iter().map(|p| p.map(&mut f)).collect(),
            return_type: self.return_type.map(&mut f),
            varargs: self.varargs.map(|p| p.into_iter().map(|p| p.map(&mut f)).collect()),
        }
    }
}

/// A method signature for a managed method.
pub type ManagedMethod<T> = MethodSignature<CallingConvention, T>;
/// A method signature for a method that may be unmanaged (e.g. for a function pointer).
pub type MaybeUnmanagedMethod<T> = MethodSignature<StandAloneCallingConvention, T>;
impl<T> ManagedMethod<T> {
    /// Creates a new managed method signature.
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

    /// Creates a new managed instance method signature.
    pub const fn instance(return_type: ReturnType<T>, parameters: Vec<Parameter<T>>) -> Self {
        Self::new(true, return_type, parameters)
    }

    /// Creates a new managed static method signature.
    pub const fn static_member(return_type: ReturnType<T>, parameters: Vec<Parameter<T>>) -> Self {
        Self::new(false, return_type, parameters)
    }
}
