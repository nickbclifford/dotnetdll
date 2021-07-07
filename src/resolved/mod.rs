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

pub trait ResolvedDebug {
    fn show(&self, res: &crate::dll::Resolution) -> String;
}
