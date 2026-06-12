pub mod assembly;
pub mod attribute;
pub mod body;
pub mod generic;
pub mod il;
pub mod members;
pub mod module;
pub mod resource;
pub mod signature;
pub mod types;

/// Member accessibility levels used across resolved metadata items.
///
/// This maps the Common Type System accessibility categories to ergonomic Rust variants.
/// Conceptually, this is the same set of access levels used for .NET members and nested types
/// (ECMA-335, I.8.5.3), with C# keyword equivalents:
/// `private`, `private protected`, `internal`, `protected`, `protected internal`, and `public`.
///
/// For top-level type visibility (`public` vs. `not public`), see
/// [`crate::resolved::types::Accessibility`].
#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Copy, Clone)]
pub enum Accessibility {
    /// Accessible only within the declaring type (`private`).
    Private,
    /// Accessible by derived types in the same assembly (`private protected`).
    FamilyANDAssembly,
    /// Accessible from any type in the same assembly (`internal`).
    Assembly,
    /// Accessible by derived types (`protected`).
    Family,
    /// Accessible by derived types or from the same assembly (`protected internal`).
    FamilyORAssembly,
    /// Accessible from anywhere (`public`).
    Public,
}

/// Construct an [`Accessibility`] value using C#-style keywords.
///
/// This is a tiny convenience macro intended for examples and builders.
///
/// ```rust
/// use dotnetdll::prelude::*;
///
/// let a = access!(public);
/// let a = access!(private);
/// let a = access!(protected internal);
/// let a = access!(private protected);
/// ```
#[macro_export]
macro_rules! access {
    (public) => {
        Accessibility::Public
    };
    (private) => {
        Accessibility::Private
    };
    (protected) => {
        Accessibility::Family
    };
    (internal) => {
        Accessibility::Assembly
    };
    (protected internal) => {
        Accessibility::FamilyORAssembly
    };
    (private protected) => {
        Accessibility::FamilyANDAssembly
    };
}

use std::fmt::{Display, Formatter};

impl Display for Accessibility {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        use Accessibility::*;

        write!(
            f,
            "{}",
            match *self {
                Private => "private",
                FamilyANDAssembly => "private protected",
                Assembly => "internal",
                Family => "protected",
                FamilyORAssembly => "protected internal",
                Public => "public",
            }
        )
    }
}

/// Context-aware formatting for resolved metadata values.
///
/// Unlike [`std::fmt::Display`], implementations can use a [`crate::resolution::Resolution`]
/// to resolve typed indices into human-readable names while formatting.
#[allow(clippy::module_name_repetitions)]
pub trait ResolvedDebug {
    /// Returns a display-oriented string using `res` as lookup context.
    fn show(&self, res: &crate::resolution::Resolution) -> String;
}
