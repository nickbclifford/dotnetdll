use super::{attribute::Attribute, types, ResolvedDebug};
use crate::resolution::Resolution;

#[derive(Debug)]
pub enum Variance {
    Invariant,
    Covariant,
    Contravariant,
}

#[derive(Debug)]
pub struct SpecialConstraint {
    pub reference_type: bool,
    pub value_type: bool,
    pub has_default_constructor: bool,
}
impl SpecialConstraint {
    pub fn is_empty(&self) -> bool {
        !(self.reference_type || self.value_type || self.has_default_constructor)
    }
}

#[derive(Debug)]
pub struct GenericConstraint<'a, ConstraintType> {
    pub attributes: Vec<Attribute<'a>>,
    pub custom_modifiers: Vec<types::CustomTypeModifier>,
    pub constraint_type: ConstraintType,
}

#[derive(Debug)]
pub struct Generic<'a, ConstraintType> {
    pub attributes: Vec<Attribute<'a>>,
    pub sequence: usize,
    pub name: &'a str,
    pub variance: Variance,
    pub special_constraint: SpecialConstraint,
    pub type_constraints: Vec<GenericConstraint<'a, ConstraintType>>,
}

pub type TypeGeneric<'a> = Generic<'a, types::MemberType>;
pub type MethodGeneric<'a> = Generic<'a, types::MethodType>;

impl<T: ResolvedDebug> ResolvedDebug for Vec<Generic<'_, T>> {
    fn show(&self, _: &Resolution) -> String {
        use std::fmt::Write;

        let mut buf = String::new();

        if !self.is_empty() {
            write!(
                buf,
                "<{}>",
                self.iter()
                    .map(|p| p.name)
                    .collect::<Vec<&str>>()
                    .join(", ")
            )
            .unwrap();
        }

        buf
    }
}

pub fn show_constraints<T: ResolvedDebug>(
    v: &[Generic<'_, T>],
    res: &Resolution,
) -> Option<String> {
    if v.iter()
        .any(|g| !(g.special_constraint.is_empty() && g.type_constraints.is_empty()))
    {
        Some(
            v.iter()
                .map(|g| {
                    let mut constraints = Vec::new();
                    if g.special_constraint.reference_type {
                        constraints.push("class".to_string());
                    }
                    if g.special_constraint.value_type {
                        constraints.push("struct".to_string());
                    }
                    if g.special_constraint.has_default_constructor {
                        constraints.push("new()".to_string());
                    }
                    constraints.extend(
                        g.type_constraints
                            .iter()
                            .map(|t| t.constraint_type.show(res)),
                    );

                    if constraints.is_empty() {
                        String::new()
                    } else {
                        format!("where {} : {}", g.name, constraints.join(", "))
                    }
                })
                .collect::<Vec<_>>()
                .join(" "),
        )
    } else {
        None
    }
}
