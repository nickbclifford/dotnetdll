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

#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Copy, Clone)]
pub enum Accessibility {
    Private,
    FamilyANDAssembly,
    Assembly,
    Family,
    FamilyORAssembly,
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

#[allow(clippy::module_name_repetitions)]
pub trait ResolvedDebug {
    fn show(&self, res: &crate::resolution::Resolution) -> String;
}
